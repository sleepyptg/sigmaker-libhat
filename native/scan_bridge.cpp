// libhat-sigmaker native scan bridge
//
// A small, ABI-stable C layer over libhat's signature parser and SIMD scanner.
// The IDA plugin loads this DLL with ctypes, so it works with every CPython
// version bundled with IDA and never needs the IDA SDK.
//
// This file is built as a shared library (`libhat_scan`) and links libhat
// statically. See CMakeLists.txt.

#include <libhat/scanner.hpp>
#include <libhat/signature.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <vector>

#if defined(_WIN32)
    #define LIBHAT_SCAN_API extern "C" __declspec(dllexport)
#else
    #define LIBHAT_SCAN_API extern "C" __attribute__((visibility("default")))
#endif

#ifndef LIBHAT_SCAN_VERSION_STRING
    #define LIBHAT_SCAN_VERSION_STRING "0.1.0"
#endif

namespace {

constexpr int status_ok = 0;
constexpr int status_invalid_argument = 1;
constexpr int status_invalid_signature = 2;
constexpr int status_out_of_memory = 3;
constexpr int status_buffer_too_large = 4;

struct scan_signature {
    hat::signature value;
};

[[nodiscard]] bool valid_alignment(const int alignment) {
    return alignment == 1 || alignment == 4 || alignment == 16;
}

[[nodiscard]] hat::scan_alignment to_alignment(const int alignment) {
    switch (alignment) {
        case 4:
            return hat::scan_alignment::X4;
        case 16:
            return hat::scan_alignment::X16;
        default:
            return hat::scan_alignment::X1;
    }
}

[[nodiscard]] bool valid_scan_args(
    const scan_signature* signature,
    const void*            buffer,
    const std::size_t      size,
    const int              alignment
) {
    if (signature == nullptr || (!buffer && size != 0) || !valid_alignment(alignment)) {
        return false;
    }
    return !signature->value.empty();
}

// Count matches in bounded chunks so a one-byte pattern cannot force a huge
// intermediate allocation. `limit == 0` means "count every match".
[[nodiscard]] std::size_t count_matches(
    const std::byte*       begin,
    const std::byte*       end,
    const scan_signature&  signature,
    const hat::scan_alignment alignment,
    const hat::scan_hint   hints,
    const std::size_t      limit
) {
    constexpr std::size_t chunk_size = 256;

    std::array<hat::const_scan_result, chunk_size> chunk{};
    std::size_t total = 0;
    const std::byte* cursor = begin;

    while (cursor < end) {
        const std::size_t remaining = limit == 0 ? chunk_size : limit - total;
        const std::size_t want = std::min(chunk_size, remaining);
        if (want == 0) {
            break;
        }

        const auto [next, out] = hat::find_all_pattern(
            cursor, end,
            chunk.data(), chunk.data() + want,
            signature.value, alignment, hints
        );

        const auto found = static_cast<std::size_t>(out - chunk.data());
        total += found;

        if (found < want) {
            break;
        }
        cursor = next;
    }

    return total;
}

// Fill `offsets` with the byte offset (relative to `begin`) of every match.
// Returns the number written. Stops when either the range or output is full.
[[nodiscard]] std::size_t fill_matches(
    const std::byte*       begin,
    const std::byte*       end,
    const scan_signature&  signature,
    const hat::scan_alignment alignment,
    const hat::scan_hint   hints,
    std::uint64_t*         offsets,
    const std::size_t      capacity
) {
    constexpr std::size_t chunk_size = 512;

    std::array<hat::const_scan_result, chunk_size> chunk{};
    std::size_t filled = 0;
    const std::byte* cursor = begin;

    while (cursor < end && filled < capacity) {
        const std::size_t want = std::min(chunk_size, capacity - filled);
        const auto [next, out] = hat::find_all_pattern(
            cursor, end,
            chunk.data(), chunk.data() + want,
            signature.value, alignment, hints
        );

        const auto found = static_cast<std::size_t>(out - chunk.data());
        for (std::size_t i = 0; i < found; ++i) {
            offsets[filled++] = static_cast<std::uint64_t>(chunk[i].get() - begin);
        }

        if (found < want) {
            break;
        }
        cursor = next;
    }

    return filled;
}

// Growable result buffer for the single-pass find-all entry point. It is
// allocated here and released by libhat_scan_free_result so a caller never
// has to know the match count in advance (the old count-then-scan pair walked
// the whole buffer twice for every query).
class offset_buffer {
public:
    offset_buffer() = default;
    offset_buffer(const offset_buffer&) = delete;
    offset_buffer& operator=(const offset_buffer&) = delete;

    ~offset_buffer() {
        std::free(data_);
    }

    [[nodiscard]] bool append(const std::uint64_t* values, const std::size_t count) {
        if (count == 0) {
            return true;
        }
        if (!reserve(size_ + count)) {
            return false;
        }
        std::memcpy(data_ + size_, values, count * sizeof(std::uint64_t));
        size_ += count;
        return true;
    }

    [[nodiscard]] bool reserve(const std::size_t required) {
        if (required <= capacity_) {
            return true;
        }
        std::size_t next = capacity_ != 0 ? capacity_ : 1024;
        while (next < required) {
            const std::size_t doubled = next * 2;
            next = doubled > next ? doubled : required;
        }
        auto* grown = static_cast<std::uint64_t*>(
            std::realloc(data_, next * sizeof(std::uint64_t))
        );
        if (grown == nullptr) {
            return false;
        }
        data_ = grown;
        capacity_ = next;
        return true;
    }

    [[nodiscard]] std::uint64_t* release() {
        auto* data = data_;
        data_ = nullptr;
        size_ = 0;
        capacity_ = 0;
        return data;
    }

    [[nodiscard]] std::size_t size() const {
        return size_;
    }

private:
    std::uint64_t* data_ = nullptr;
    std::size_t    size_ = 0;
    std::size_t    capacity_ = 0;
};

// One pass over `[begin, end)` that collects match offsets into `out`.
// `cap` limits the collected count (0 means unlimited). Returns false only on
// allocation failure; `*complete` reports whether the scan reached `end`.
[[nodiscard]] bool collect_matches(
    const std::byte*       begin,
    const std::byte*       end,
    const scan_signature&  signature,
    const hat::scan_alignment alignment,
    const hat::scan_hint   hints,
    const std::size_t      cap,
    offset_buffer&         out,
    bool&                  complete
) {
    constexpr std::size_t chunk_size = 1024;

    std::array<hat::const_scan_result, chunk_size> chunk{};
    std::uint64_t offsets[chunk_size];
    const std::byte* cursor = begin;
    complete = false;

    while (cursor < end) {
        std::size_t want = chunk_size;
        if (cap != 0) {
            const std::size_t room = cap - out.size();
            want = std::min(want, room);
            if (want == 0) {
                return true;
            }
        }

        const auto [next, outEnd] = hat::find_all_pattern(
            cursor, end,
            chunk.data(), chunk.data() + want,
            signature.value, alignment, hints
        );

        const auto found = static_cast<std::size_t>(outEnd - chunk.data());
        for (std::size_t i = 0; i < found; ++i) {
            offsets[i] = static_cast<std::uint64_t>(chunk[i].get() - begin);
        }
        if (!out.append(offsets, found)) {
            return false;
        }

        if (found < want) {
            complete = true;
            return true;
        }
        cursor = next;
    }

    complete = true;
    return true;
}

// Builds 8-byte value/mask words for the byte range [begin, begin + word_count * 8).
// The remainder of the pattern is compared byte-wise by the caller.
constexpr std::size_t max_word_count = 32; // 256 signature bytes inline

void build_signature_words(
    const std::uint8_t* values,
    const std::uint8_t* masks,
    const std::size_t   begin,
    std::size_t         word_count,
    std::uint64_t*      value_words,
    std::uint64_t*      mask_words
) {
    std::size_t index = begin;
    std::size_t word = 0;
    for (; word < word_count; ++word) {
        std::uint64_t value = 0;
        std::uint64_t mask = 0;
        for (std::size_t byte = 0; byte < 8; ++byte) {
            const std::uint64_t shift = byte * 8;
            value |= static_cast<std::uint64_t>(values[index]) << shift;
            mask |= static_cast<std::uint64_t>(masks[index]) << shift;
            ++index;
        }
        value_words[word] = value & mask;
        mask_words[word] = mask;
    }
}

} // namespace

LIBHAT_SCAN_API const char* libhat_scan_version() {
    return LIBHAT_SCAN_VERSION_STRING;
}

LIBHAT_SCAN_API const char* libhat_scan_status_string(const int status) {
    switch (status) {
        case status_ok:               return "success";
        case status_invalid_argument: return "invalid argument";
        case status_invalid_signature:return "invalid signature";
        case status_out_of_memory:    return "out of memory";
        case status_buffer_too_large: return "buffer too large for a 32-bit byte index";
        default:                      return "unknown status";
    }
}

LIBHAT_SCAN_API int libhat_scan_create_signature(
    const std::uint8_t* bytes,
    const std::uint8_t* masks,
    const std::size_t   size,
    scan_signature**    signature_out
) {
    if (signature_out == nullptr || (size != 0 && (!bytes || !masks))) {
        return status_invalid_argument;
    }
    *signature_out = nullptr;

    auto* result = new (std::nothrow) scan_signature{};
    if (result == nullptr) {
        return status_out_of_memory;
    }

    try {
        result->value.resize(size);
    } catch (const std::bad_alloc&) {
        delete result;
        return status_out_of_memory;
    }

    for (std::size_t i = 0; i < size; ++i) {
        result->value[i] = hat::signature_element{
            static_cast<std::byte>(bytes[i]),
            static_cast<std::byte>(masks[i])
        };
    }

    *signature_out = result;
    return status_ok;
}

LIBHAT_SCAN_API int libhat_scan_parse_signature(
    const char*      pattern,
    scan_signature** signature_out
) {
    if (pattern == nullptr || signature_out == nullptr) {
        return status_invalid_argument;
    }
    *signature_out = nullptr;

    const auto parsed = hat::parse_signature(pattern);
    if (!parsed.has_value()) {
        return status_invalid_signature;
    }

    auto* result = new (std::nothrow) scan_signature{std::move(parsed).value()};
    if (result == nullptr) {
        return status_out_of_memory;
    }

    *signature_out = result;
    return status_ok;
}

LIBHAT_SCAN_API void libhat_scan_free_signature(scan_signature* signature) {
    delete signature;
}

LIBHAT_SCAN_API std::size_t libhat_scan_signature_size(const scan_signature* signature) {
    return signature == nullptr ? 0 : signature->value.size();
}

LIBHAT_SCAN_API int libhat_scan_count(
    const scan_signature* signature,
    const void*           buffer,
    const std::size_t     size,
    const int             alignment,
    const std::uint64_t   hints,
    const std::size_t     limit,
    std::size_t*          count_out
) {
    if (count_out == nullptr || !valid_scan_args(signature, buffer, size, alignment)) {
        return status_invalid_argument;
    }
    *count_out = 0;

    if (size == 0) {
        return status_ok;
    }

    const auto* begin = static_cast<const std::byte*>(buffer);
    *count_out = count_matches(
        begin, begin + size,
        *signature,
        to_alignment(alignment),
        static_cast<hat::scan_hint>(hints),
        limit
    );
    return status_ok;
}

LIBHAT_SCAN_API int libhat_scan_find_all(
    const scan_signature* signature,
    const void*           buffer,
    const std::size_t     size,
    std::uint64_t*        offsets,
    const std::size_t     capacity,
    const int             alignment,
    const std::uint64_t   hints,
    std::size_t*          count_out
) {
    if (count_out == nullptr || !valid_scan_args(signature, buffer, size, alignment)
        || (capacity != 0 && offsets == nullptr)) {
        return status_invalid_argument;
    }
    *count_out = 0;

    if (size == 0 || capacity == 0) {
        return status_ok;
    }

    const auto* begin = static_cast<const std::byte*>(buffer);
    *count_out = fill_matches(
        begin, begin + size,
        *signature,
        to_alignment(alignment),
        static_cast<hat::scan_hint>(hints),
        offsets,
        capacity
    );
    return status_ok;
}

LIBHAT_SCAN_API int libhat_scan_find_first(
    const scan_signature* signature,
    const void*           buffer,
    const std::size_t     size,
    const int             alignment,
    const std::uint64_t   hints,
    std::uint64_t*        offset_out
) {
    if (offset_out == nullptr || !valid_scan_args(signature, buffer, size, alignment)) {
        return status_invalid_argument;
    }
    *offset_out = std::numeric_limits<std::uint64_t>::max();

    if (size == 0) {
        return status_ok;
    }

    const auto* begin = static_cast<const std::byte*>(buffer);
    const auto result = hat::find_pattern(
        begin, begin + size,
        signature->value,
        to_alignment(alignment),
        static_cast<hat::scan_hint>(hints)
    );

    if (result.has_result()) {
        *offset_out = static_cast<std::uint64_t>(result.get() - begin);
    }
    return status_ok;
}

// Single-pass variant of libhat_scan_find_all. The result buffer is allocated
// here (and released by libhat_scan_free_result), so callers do not need a
// separate counting scan to size it. `max_matches` reports truncation exactly
// by collecting one extra match and then dropping it.
LIBHAT_SCAN_API int libhat_scan_find_all_alloc(
    const scan_signature* signature,
    const void*           buffer,
    const std::size_t     size,
    const int             alignment,
    const std::uint64_t   hints,
    const std::size_t     limit,
    const std::size_t     max_matches,
    std::uint64_t**       offsets_out,
    std::size_t*          count_out,
    int*                  truncated_out
) {
    if (offsets_out == nullptr || count_out == nullptr || truncated_out == nullptr
        || !valid_scan_args(signature, buffer, size, alignment)) {
        return status_invalid_argument;
    }
    *offsets_out = nullptr;
    *count_out = 0;
    *truncated_out = 0;

    if (size == 0) {
        return status_ok;
    }

    // `limit` is an intentional early stop, so it never implies truncation.
    // `max_matches` caps the buffer, but one extra match is collected to tell
    // "exactly max_matches" apart from "more than max_matches".
    std::size_t cap = limit;
    if (max_matches != 0) {
        const std::size_t probe = max_matches < std::numeric_limits<std::size_t>::max()
            ? max_matches + 1
            : max_matches;
        cap = cap == 0 ? probe : std::min(cap, probe);
    }

    const auto* begin = static_cast<const std::byte*>(buffer);
    offset_buffer collected;
    bool complete = false;
    if (!collect_matches(
            begin, begin + size,
            *signature,
            to_alignment(alignment),
            static_cast<hat::scan_hint>(hints),
            cap,
            collected,
            complete)) {
        return status_out_of_memory;
    }

    std::size_t count = collected.size();
    if (max_matches != 0 && count > max_matches) {
        count = max_matches;
        *truncated_out = 1;
    }
    *count_out = count;
    if (count != 0) {
        *offsets_out = collected.release();
    }
    return status_ok;
}

LIBHAT_SCAN_API void libhat_scan_free_result(std::uint64_t* offsets) {
    std::free(offsets);
}

// Compacts `candidates` in place, keeping the entries whose full masked
// pattern matches. This replaces a chain of per-byte refine_offsets calls: the
// same candidates are probed once against the whole pattern, so the working
// set is a couple of cache lines per candidate instead of one random line per
// pattern byte, and Python pays one call instead of one per byte.
LIBHAT_SCAN_API std::size_t libhat_scan_verify_offsets(
    const void*          buffer,
    const std::size_t    size,
    std::uint64_t*       candidates,
    const std::size_t    count,
    const std::uint8_t*  values,
    const std::uint8_t*  masks,
    const std::size_t    pattern_size,
    const std::size_t    start_index
) {
    if (count == 0) {
        return 0;
    }
    if (buffer == nullptr || candidates == nullptr || values == nullptr
        || masks == nullptr || pattern_size == 0 || start_index > pattern_size) {
        return 0;
    }

    const auto* data = static_cast<const std::uint8_t*>(buffer);
    const std::size_t remaining = pattern_size - start_index;
    const std::size_t word_count = std::min(remaining / 8, max_word_count);
    const std::size_t word_bytes = word_count * 8;

    std::uint64_t value_words[max_word_count];
    std::uint64_t mask_words[max_word_count];
    build_signature_words(
        values, masks, start_index,
        word_count, value_words, mask_words
    );

    std::size_t written = 0;
    for (std::size_t read = 0; read < count; ++read) {
        const std::uint64_t start = candidates[read];
        if (start + pattern_size > size) {
            continue;
        }

        const auto* candidate = data + start;
        bool matched = true;
        for (std::size_t word = 0; word < word_count; ++word) {
            std::uint64_t chunk;
            std::memcpy(&chunk, candidate + start_index + word * 8, sizeof(chunk));
            if ((chunk & mask_words[word]) != value_words[word]) {
                matched = false;
                break;
            }
        }
        if (matched) {
            // Tail bytes, plus every byte past the inline word budget.
            for (std::size_t index = start_index + word_bytes; index < pattern_size; ++index) {
                const std::uint8_t mask = masks[index];
                if (mask == 0) {
                    continue;
                }
                if ((candidate[index] & mask) != (values[index] & mask)) {
                    matched = false;
                    break;
                }
            }
        }

        if (matched) {
            candidates[written++] = start;
        }
    }

    return written;
}

// Builds a 65537-entry head table followed by every 2-byte window position,
// grouped by the 16-bit key (data[i] << 8 | data[i + 1]). The layout matches
// the acceleration contract used by the original ida-sigmaker Cython kernels.
LIBHAT_SCAN_API int libhat_scan_build_byte_index(
    const void*     buffer,
    const std::size_t size,
    std::uint32_t*  heads,
    std::uint32_t*  positions
) {
    if ((!buffer && size != 0) || heads == nullptr) {
        return status_invalid_argument;
    }
    if (size < 2) {
        return status_invalid_argument;
    }
    if (size - 1 > std::numeric_limits<std::uint32_t>::max()) {
        return status_buffer_too_large;
    }
    if (positions == nullptr) {
        return status_invalid_argument;
    }

    const auto* data = static_cast<const std::uint8_t*>(buffer);
    std::memset(heads, 0, 65537 * sizeof(std::uint32_t));

    for (std::size_t i = 0; i + 1 < size; ++i) {
        const std::uint32_t key = (static_cast<std::uint32_t>(data[i]) << 8)
                                | static_cast<std::uint32_t>(data[i + 1]);
        ++heads[key + 1];
    }
    for (std::size_t i = 1; i <= 65536; ++i) {
        heads[i] += heads[i - 1];
    }

    // A per-thread cursor table avoids a 256 KiB allocation on every build.
    thread_local std::array<std::uint32_t, 65537> cursor;
    cursor[65536] = 0; // keep tools from flagging the unused element
    std::memcpy(cursor.data(), heads, 65537 * sizeof(std::uint32_t));
    for (std::size_t i = 0; i + 1 < size; ++i) {
        const std::uint32_t key = (static_cast<std::uint32_t>(data[i]) << 8)
                                | static_cast<std::uint32_t>(data[i + 1]);
        positions[cursor[key]++] = static_cast<std::uint32_t>(i);
    }

    return status_ok;
}

LIBHAT_SCAN_API std::size_t libhat_scan_seed_offsets(
    const std::uint32_t* raw_positions,
    const std::size_t    raw_count,
    const std::size_t    seed_offset,
    const std::size_t    pattern_size,
    const std::size_t    buffer_size,
    std::uint64_t*       candidates,
    const std::size_t    capacity
) {
    if ((raw_count != 0 && raw_positions == nullptr) || candidates == nullptr) {
        return 0;
    }

    std::size_t count = 0;
    for (std::size_t i = 0; i < raw_count && count < capacity; ++i) {
        const std::uint64_t position = raw_positions[i];
        if (position < seed_offset) {
            continue;
        }
        const std::uint64_t start = position - seed_offset;
        if (start + pattern_size > buffer_size) {
            continue;
        }
        candidates[count++] = start;
    }
    return count;
}

LIBHAT_SCAN_API std::size_t libhat_scan_refine_offsets(
    const void*           buffer,
    const std::size_t     size,
    std::uint64_t*        candidates,
    const std::size_t     count,
    const std::size_t     index,
    const std::uint8_t    value,
    const std::uint8_t    mask
) {
    if (!buffer || !candidates) {
        return 0;
    }

    const auto* data = static_cast<const std::uint8_t*>(buffer);
    const std::uint8_t target = static_cast<std::uint8_t>(value & mask);

    std::size_t write = 0;
    for (std::size_t read = 0; read < count; ++read) {
        const std::uint64_t position = static_cast<std::uint64_t>(candidates[read]) + index;
        if (position < size && (data[position] & mask) == target) {
            candidates[write++] = candidates[read];
        }
    }
    return write;
}

LIBHAT_SCAN_API std::size_t libhat_scan_filter_offsets(
    std::uint64_t*       candidates,
    const std::size_t    count,
    const std::size_t    pattern_size,
    const std::uint64_t* range_starts,
    const std::uint64_t* range_ends,
    const std::size_t    range_count
) {
    if (candidates == nullptr || (range_count != 0 && (!range_starts || !range_ends))) {
        return 0;
    }

    std::size_t range_index = 0;
    std::size_t write = 0;

    for (std::size_t read = 0; read < count; ++read) {
        const std::uint64_t start = candidates[read];
        while (range_index < range_count && start >= range_ends[range_index]) {
            ++range_index;
        }
        if (range_index == range_count) {
            break;
        }
        if (start >= range_starts[range_index]
            && start + pattern_size <= range_ends[range_index]) {
            candidates[write++] = candidates[read];
        }
    }
    return write;
}

#include <iostream>
#include <fstream>
#include <cstring>
#include <random>
#include "sha256.h"


class arcipher_t 
{
public:
    // Aliases.
    using byte_t = unsigned char;

    /** default constuctor. */ 
    arcipher_t()
    : m_cipher(nullptr), m_size(0), m_engine_cursor(0) {}

    /** Add bytes to the cipher object. */
    void add(const byte_t* buffer, size_t size)
    {
        //  Avoid redundant memory allocations and copying if size is passed 0.
        if (! size)
        {
            return;
        }

        // Reallocate enough memory to add cipher of given buffer.
        byte_t* temp = new byte_t[m_size + size];
        memcpy(temp, m_cipher, m_size);
        delete[] m_cipher;
        m_cipher = temp;
    
        std::uniform_int_distribution<uint32_t> dist(0x0, 0xFF);

        // Iterate over all the bytes of buffer.
        for (size_t i = 0; i < size; i++)
        {
            // Compute cipher and store in m_cipher buffer character by character.
            m_cipher[m_size++] = 
            buffer[i] ^ dist(mt_engines[m_engine_cursor % block_count]);
            m_engine_cursor++;
        }
    }

    /** Resets the state of the cipher to a default state. */
    void reset()
    {
        // Free all associated resources.
        delete[] m_cipher;
        m_cipher = nullptr;

        // Reset m_engine_cursor.
        m_engine_cursor = 0;

        // Reset m_size.
        m_size = 0;

        // Reset all SRN generators.
        for (size_t i = 0; i < block_count; i++) 
        {
            mt_engines[i].seed();
        }
    }

    /** Resets the state of the cipher to based on a given keyword. */
    void reset(const char* keyword, size_t size)
    {
        // Free all associated resources.
        delete[] m_cipher;
        m_cipher = nullptr;

        // Reset m_size.
        m_size = 0;

        // Reset m_engine_cursor.
        m_engine_cursor = 0;

        // Calculate seed for all SRN generators.
        SHA256 sha256;
        byte_t raw_hash[SHA256::HashBytes];
        sha256.add(keyword, size);
        sha256.getHash(raw_hash);

        // Reset all SRN generators using calculated seeds.
        for (size_t i = 0; i < block_count; i++) 
        {
            mt_engines[i].seed(*(uint32_t*)(raw_hash + (sizeof(uint32_t) * i)));
        }
    }

    /** Returns the current size of the cipher buffer (internal) in bytes. */
    size_t size() const { return m_size; }

    /** Writes cipher to buffer and flushes internal buffer. */
    void dump(byte_t* buffer, size_t* size)
    {
        // Write cipher to buffer.
        memcpy(buffer, m_cipher, m_size);

        // Flush internal buffer.
        delete[] m_cipher;
        m_cipher = nullptr;
        m_size = 0;

        // set size is no NULL, it's set to total number of SRN generator calls 
        // (which equals the total number of encrypted bytes so far).
        if (size)
        {
            *size = m_engine_cursor;
        }
    }

    /** Destructor. */
    ~arcipher_t()
    {
        delete[] m_cipher;
    } 

private:
    byte_t* m_cipher;                           // Buffer containing the ciper.
    size_t m_size;                              // Size of current cipher buffer in memory.
    size_t m_engine_cursor;                     // Total number of SRN generator/engine call
                                                // since last reset call.
    static const size_t block_count = 
        SHA256::HashBytes/sizeof(uint32_t);
    std::mt19937 mt_engines[block_count];       // SRN generators.
};


int main(int argc, char** argv)
{
    // Ensure proper usage.
    if (argc != 3)
    {
        std::cerr << "usage:" << argv[0] << " <input-filename> <keyword>" << std::endl;
        return -1;
    }

    // Remember input filename and keyword.
    std::string input_filename = argv[1];
    std::string keyword = argv[2];
    
    // Open input file for reading.
    std::ifstream infile(input_filename, std::ios::binary | std::ios::in);
    if (! infile.is_open())
    {
        std::cerr << "Failed to open " << input_filename << std::endl;
        return 1;
    }

    // Open output file for reading.
    std::ofstream outfile("output", std::ios::out | std::ios::binary);

    // Create a cipher object.
    arcipher_t arcipher;
    arcipher.reset(keyword.c_str(), keyword.size());

    // Read input file incrementally.
    const size_t chunk_size = 256;
    arcipher_t::byte_t* chunk = new arcipher_t::byte_t[chunk_size];
    std::size_t bytes_read;
    do {
        bytes_read = infile.read((char*)chunk, chunk_size).gcount();
        arcipher.add(chunk, bytes_read);

        // Write output incrementally.
        // TODO: Avoid copying. Write directly from the cipher object.
        size_t buffer_size = arcipher.size();
        arcipher_t::byte_t* out = new arcipher_t::byte_t[buffer_size];
        arcipher.dump(out, NULL);
        outfile.write((const char*)out, buffer_size);
        delete[] out;
    } while (bytes_read > 0);
    delete[] chunk;
    
    // Close files.
    outfile.close();
    infile.close();

    return 0;
}

#include <iostream>
#include <random>
#include <fstream>
#include <filesystem>
#include "sha256.h"

using byte_t = unsigned char;

void convert(const byte_t* src, byte_t* dest, size_t size, const char* keyword, size_t k_size)
{
    SHA256 sha256;
    byte_t raw_hash[SHA256::HashBytes];
    sha256.add(keyword, k_size);
    sha256.getHash(raw_hash);
    const uint32_t block_size = sizeof(uint32_t);
    const uint32_t block_count = SHA256::HashBytes / block_size;
    std::mt19937 mt_engine[block_count];
    for (uint32_t i = 0; i < block_count; i++)
    {
        uint32_t sd = *(uint32_t*)(raw_hash + (block_size * i));
        mt_engine[i].seed(sd);
    }

    std::uniform_int_distribution<uint32_t> dist(0x0, 0xFF);
    for (uint32_t i = 0; i < size; i++)
    {
       dest[i] = src[i] ^ dist(mt_engine[i % block_count]);
    }
}

int main(int argc, char** argv)
{
    // Ensure proper usage.
    if (argc != 3)
    {
        std::cerr << "usage:" << argv[0] << " <input-filename> <keyword>" << std::endl;
        return -1;
    }

    // Extract input filename and keyword.
    std::string input_filename = argv[1];
    std::string keyword = argv[2];
    
    // Open input file for reading.
    std::ifstream infile(input_filename, std::ios_base::binary | std::ios_base::in);
    if (! infile.is_open())
    {
        std::cerr << "Failed to open file" << std::endl;
        return -1;
    }

    // Open output file for reading.
    std::ofstream outfile("output", std::ios_base::out | std::ios_base::binary);

    // Load entire input file into memory.
    int buffer_capacity = std::filesystem::file_size(input_filename);
    byte_t* buffer = new byte_t[buffer_capacity];
    int cur = 0;
    char c;
    while (infile.read(&c, 0x1))
    {
        buffer[cur] = c;
        cur++;
    }
    buffer[cur] = 0x0;

    // Encrypt/Decrypt.
    byte_t* out = new byte_t[cur];
    convert(buffer, out, cur, keyword.c_str(), keyword.size());

    // Write output to file.
    for (int i = 0; i < cur; i++)
    {
        outfile.write((char*)(out + i), 1);
    }

    outfile.close();
    infile.close();
}

//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE crypto3_marshalling_field_element_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/detail/marshalling.hpp>

#include <nil/crypto3/marshalling/types/algebra/field_element.hpp>

template <typename TIter>
void print_byteblob(TIter iter_begin, TIter iter_end){
    for (TIter it = iter_begin; 
         it != iter_end;
         it++){
        std::cout << std::hex << int(*it) << std::endl;
    }
}

template<typename FieldType, 
         typename Endianness>
void test_field_element(
    typename FieldType::value_type val) {

    using namespace nil::crypto3::marshalling;

    std::size_t units_bits = 8;
    using unit_type = unsigned char;
    using field_element_type = types::field_element<
        nil::marshalling::field_type<
        Endianness>,
        FieldType>;

    field_element_type test_val = 
        types::fill_field_element<FieldType,
            Endianness>(val);

    std::size_t unitblob_size = 
        test_val.length();

    std::vector<unit_type> cv;
    cv.resize(unitblob_size, 0x00);

    auto write_iter = cv.begin();

    nil::marshalling::status_type status =  
        test_val.write(write_iter, 
            cv.size());

    field_element_type test_val_read;

    auto read_iter = cv.begin();
    status = 
        test_val_read.read(read_iter, 
                cv.size());
    
    typename FieldType::value_type read_val = 
        types::constuct_field_element<FieldType, 
            Endianness>(
                test_val_read);

    BOOST_CHECK(val == 
                read_val);
}

template<typename FieldType, 
         typename Endianness>
void test_field_element() {
    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 128; ++i) {
        if (!(i%16) && i){
            std::cout << std::dec << i << " tested" << std::endl;
        }
        typename FieldType::value_type val = 
            nil::crypto3::algebra::random_element<FieldType>();
        test_field_element<FieldType, Endianness>(val);
    }
}

BOOST_AUTO_TEST_SUITE(field_element_test_suite)

BOOST_AUTO_TEST_CASE(field_element_bls12_381_g1_field_be) {
    std::cout << "BLS12-381 g1 group field big-endian test started" << std::endl;
    test_field_element<nil::crypto3::algebra::curves::bls12<381>::g1_type::underlying_field_type, 
        nil::marshalling::option::big_endian>();
    std::cout << "BLS12-381 g1 group field big-endian test finished" << std::endl;
}

BOOST_AUTO_TEST_CASE(field_element_bls12_381_g1_field_le) {
    std::cout << "BLS12-381 g1 group field little-endian test started" << std::endl;
    test_field_element<nil::crypto3::algebra::curves::bls12<381>::g1_type::underlying_field_type, 
        nil::marshalling::option::little_endian>();
    std::cout << "BLS12-381 g1 group field little-endian test finished" << std::endl;
}

BOOST_AUTO_TEST_CASE(field_element_bls12_381_g2_field_be) {
    std::cout << "BLS12-381 g2 group field big-endian test started" << std::endl;
    test_field_element<nil::crypto3::algebra::curves::bls12<381>::g2_type::underlying_field_type, 
        nil::marshalling::option::big_endian>();
    std::cout << "BLS12-381 g2 group field big-endian test finished" << std::endl;
}

BOOST_AUTO_TEST_CASE(field_element_bls12_381_g2_field_le) {
    std::cout << "BLS12-381 g2 group field little-endian test started" << std::endl;
    test_field_element<nil::crypto3::algebra::curves::bls12<381>::g2_type::underlying_field_type, 
        nil::marshalling::option::little_endian>();
    std::cout << "BLS12-381 g2 group field little-endian test finished" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()

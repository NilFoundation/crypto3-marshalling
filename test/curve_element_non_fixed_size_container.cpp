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

#define BOOST_TEST_MODULE crypto3_marshalling_curve_element_non_fixed_size_container_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/container/static_vector.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/detail/marshalling.hpp>

#include <nil/crypto3/marshalling/types/algebra/curve_element.hpp>

template <typename TIter>
void print_byteblob(TIter iter_begin, TIter iter_end){
    for (TIter it = iter_begin; 
         it != iter_end;
         it++){
        std::cout << std::hex << int(*it) << std::endl;
    }
}

template<typename Endianness, 
         class CurveGroupElement, 
         std::size_t TSize>
void test_curve_element_non_fixed_size_container(
    std::vector<CurveGroupElement> val_container) {
    using namespace nil::crypto3::marshalling;
    std::size_t units_bits = 8;
    using unit_type = unsigned char;
    using CurveGroup = typename CurveGroupElement::group_type;

    using curve_element_type = types::curve_element<
        nil::marshalling::field_type<
        Endianness>,
        CurveGroup>;
    using curve_type = 
        typename CurveGroup::curve_type;

    using container_type = 
    nil::marshalling::types::array_list<
        nil::marshalling::field_type<
        Endianness>,
        curve_element_type
    >;

    std::size_t unitblob_size = 
        curve_element_type::bit_length()/units_bits + 
        ((curve_element_type::bit_length()%units_bits)?1:0);
    std::vector<unit_type> cv;
    cv.resize(unitblob_size*TSize, 0x00);

    std::vector<curve_element_type> container_data;

    for (std::size_t i=0; i<TSize; i++){
        container_data.push_back(
            curve_element_type(val_container[i]));
    }

    container_type test_val = container_type(container_data);

    container_type filled_val = 
        types::fill_curve_element_vector<CurveGroup,
            Endianness>(val_container);

    std::vector<typename CurveGroup::value_type> constructed_val = 
        types::constuct_curve_element_vector<CurveGroup, 
            Endianness>(
                filled_val);
    BOOST_CHECK(std::equal(val_container.begin(), 
                           val_container.end(), 
                           constructed_val.begin()));

    auto write_iter = cv.begin();

    nil::marshalling::status_type status =  
        test_val.write(write_iter, 
            cv.size());

    container_type test_val_read;

    auto read_iter = cv.begin();
    status = 
        test_val_read.read(read_iter, 
                cv.size());

    BOOST_CHECK(std::equal(test_val.value().begin(), 
                           test_val.value().end(),
                           test_val_read.value().begin()));
}

template<typename Endianness, 
         class CurveGroup, 
         std::size_t TSize>
void test_curve_element_non_fixed_size_container() {
    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 128; ++i) {
        std::vector<
            typename CurveGroup::value_type> 
            val_container (TSize);
        if (!(i%16) && i){
            std::cout << std::dec << i << " tested" << std::endl;
        }
        for (std::size_t i=0; i<TSize; i++){
            val_container[i] = 
                nil::crypto3::algebra::random_element<CurveGroup>();
        }
        test_curve_element_non_fixed_size_container<
            Endianness, 
            typename CurveGroup::value_type, 
            TSize>(val_container);
    }
}


BOOST_AUTO_TEST_SUITE(curve_element_non_fixed_size_container_test_suite)

BOOST_AUTO_TEST_CASE(curve_element_non_fixed_size_container_bls12_381_g1) {
    std::cout << "BLS12-381 g1 group non fixed size container test started" << std::endl;
    test_curve_element_non_fixed_size_container<
        nil::marshalling::option::big_endian, 
        nil::crypto3::algebra::curves::bls12<381>::g1_type, 
        25>();
    std::cout << "BLS12-381 g1 group non fixed size container test finished" << std::endl;
}

BOOST_AUTO_TEST_CASE(curve_element_non_fixed_size_container_bls12_381_g2) {
    std::cout << "BLS12-381 g2 group non fixed size container test started" << std::endl;
    test_curve_element_non_fixed_size_container<
        nil::marshalling::option::big_endian, 
        nil::crypto3::algebra::curves::bls12<381>::g2_type, 
        5>();
    std::cout << "BLS12-381 g2 group non fixed size container test finished" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
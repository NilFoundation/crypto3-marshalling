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

#define BOOST_TEST_MODULE crypto3_marshalling_integral_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
// #include "test.hpp"
#include <iostream>
#include <iomanip>

#include <nil/marshalling/status_type.hpp>
// #include <nil/marshalling/types/array_list.hpp>
// #include <nil/marshalling/field_type.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/crypto3/marshalling/types/integral.hpp>
#include <nil/marshalling/field_type.hpp>

template<class T>
struct unchecked_type {
    typedef T type;
};

template<unsigned MinBits, unsigned MaxBits, nil::crypto3::multiprecision::cpp_integer_type SignType,
         nil::crypto3::multiprecision::cpp_int_check_type Checked, class Allocator,
         nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
struct unchecked_type<nil::crypto3::multiprecision::number<
    nil::crypto3::multiprecision::cpp_int_backend<MinBits, MaxBits, SignType, Checked, Allocator>,
    ExpressionTemplates>> {
    typedef nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_int_backend<MinBits, MaxBits, SignType,
                                                      nil::crypto3::multiprecision::unchecked, Allocator>,
        ExpressionTemplates>
        type;
};

template<class T>
T generate_random() {
    typedef typename unchecked_type<T>::type unchecked_T;

    static const unsigned limbs = std::numeric_limits<T>::is_specialized && std::numeric_limits<T>::is_bounded ?
                                      std::numeric_limits<T>::digits / std::numeric_limits<unsigned>::digits + 3 :
                                      20;

    static boost::random::uniform_int_distribution<unsigned> ui(0, limbs);
    static boost::random::mt19937 gen;
    unchecked_T val = gen();
    unsigned lim = ui(gen);
    for (unsigned i = 0; i < lim; ++i) {
        val *= (gen.max)();
        val += gen();
    }
    return val;
}

template <typename TIter>
void print_byteblob(TIter iter_begin, TIter iter_end){
    for (TIter it = iter_begin; 
         it != iter_end;
         it++){
        std::cout << std::hex << int(*it) << std::endl;
    }
}

template<class T>
void test_round_trip_fixed_precision(T val) {
    using namespace nil::crypto3::marshalling;

    types::integral<nil::marshalling::field_type<
        nil::marshalling::option::little_endian>,
        T> test_val;

    std::vector<unsigned char> cv;
    export_bits(val, std::back_inserter(cv), 8);

    auto read_iter = cv.begin();
    nil::marshalling::status_type status = 
        test_val.read(read_iter, cv.size());
    BOOST_CHECK(status == 
        nil::marshalling::status_type::success);

    BOOST_CHECK(val == test_val.value());

    std::vector<unsigned char> test_val_byteblob;
    test_val_byteblob.resize(cv.size());
    auto write_iter = test_val_byteblob.begin();

    status = test_val.write(write_iter, test_val_byteblob.size());
	BOOST_CHECK(status == 
        nil::marshalling::status_type::success);

	BOOST_CHECK(cv == test_val_byteblob);
}

template<class T>
void test_round_trip_fixed_precision() {
    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 1000; ++i) {
        T val = generate_random<T>();
        test_round_trip_fixed_precision(val);
    }
}


// template<class T>
// void test_array_list(T val, T val2, T val3, T val4, T val5) {
//     using namespace nil::crypto3::marshalling;

//     using integral_type = types::integral<nil::marshalling::field_type<
//         nil::marshalling::option::little_endian>,
//         T>;
//     using array_type = nil::marshalling::types::array_list<
//         field_type<option::big_endian>, integral_type>;

//     std::vector<unsigned char> cv;
//     export_bits(val, std::back_inserter(cv), 8);

//     auto read_iter = cv.begin();
//     nil::marshalling::status_type status = 
//         test_val.read(read_iter, cv.size());
//     BOOST_CHECK(status == 
//         nil::marshalling::status_type::success);

//     BOOST_CHECK(val == test_val.value());

//     std::vector<unsigned char> test_val_byteblob;
//     test_val_byteblob.resize(cv.size());
//     auto write_iter = test_val_byteblob.begin();

//     status = test_val.write(write_iter, test_val_byteblob.size());
//     BOOST_CHECK(status == 
//         nil::marshalling::status_type::success);

//     BOOST_CHECK(cv == test_val_byteblob);
// }

template<class T>
void test_array_list() {
    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 1000; ++i) {
        T val1 = generate_random<T>();
        T val2 = generate_random<T>();
        T val3 = generate_random<T>();
        T val4 = generate_random<T>();
        T val5 = generate_random<T>();
        test_array_list(val1, val2, val3, val4, val5);
    }
}

BOOST_AUTO_TEST_SUITE(integral_test_suite)

BOOST_AUTO_TEST_CASE(integral_cpp_int) {
	test_round_trip_fixed_precision<nil::crypto3::multiprecision::cpp_int>();
}

BOOST_AUTO_TEST_CASE(integral_checked_int1024) {
    test_round_trip_fixed_precision<nil::crypto3::multiprecision::checked_int1024_t>();
}

BOOST_AUTO_TEST_CASE(integral_cpp_uint512) {
    test_round_trip_fixed_precision<nil::crypto3::multiprecision::checked_uint512_t>();
}

BOOST_AUTO_TEST_CASE(integral_cpp_int_backend_64) {
    test_round_trip_fixed_precision<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
        64, 64, nil::crypto3::multiprecision::unsigned_magnitude, nil::crypto3::multiprecision::checked, void>>>();
}

BOOST_AUTO_TEST_CASE(integral_cpp_int_backend_23) {
    test_round_trip_fixed_precision<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
        23, 23, nil::crypto3::multiprecision::unsigned_magnitude, nil::crypto3::multiprecision::checked, void>>>();
}

BOOST_AUTO_TEST_SUITE_END()

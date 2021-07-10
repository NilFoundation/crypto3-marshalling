//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_SPARSE_VECTOR_HPP
#define CRYPTO3_MARSHALLING_SPARSE_VECTOR_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>
#include <nil/marshalling/types/tag.hpp>
#include <nil/marshalling/types/integral.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/zk/snark/sparse_vector.hpp>

#include <nil/crypto3/marshalling/types/algebra/curve_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                template<typename TTypeBase, 
                         typename SparseVector,
                         typename = typename std::enable_if<
                             std::is_same<SparseVector, 
                                zk::snark::sparse_vector<
                                    typename SparseVector::group_type
                                >
                             >::value,
                             bool>::type,
                         typename... TOptions>
                using sparse_vector = 
                    nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                nil::marshalling::types::integral<
                                    TTypeBase, 
                                    std::size_t
                                > 
                            >, 
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                types::curve_element<
                                    TTypeBase, 
                                    typename SparseVector::group_type
                                > 
                            >,
                            nil::marshalling::types::integral<
                                TTypeBase, 
                                std::size_t
                            > 
                        >
                    >;

                template <typename SparseVector, 
                          typename Endianness>
                sparse_vector_type<nil::marshalling::field_type<
                                Endianness>,
                                SparseVector>
                    fill_sparse_vector(SparseVector sparse_vector_inp){

                    using TTypeBase = nil::marshalling::field_type<
                                Endianness>;

                    return sparse_vector_type<nil::marshalling::field_type<
                                Endianness>,
                                SparseVector>(
                                    fill_integral_vector<std::size_t, Endianness>(sparse_vector_inp.indicies),
                                    fill_curve_element_vector<
                                        typename SparseVector::group_type, 
                                        Endianness>(sparse_vector_inp.values),
                                    integral<nil::marshalling::field_type<Endianness>, 
                                             std::size_t>(sparse_vector_inp.domain_size_));
                }

            }    // namespace types
        }        // namespace marshalling
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_SPARSE_VECTOR_HPP

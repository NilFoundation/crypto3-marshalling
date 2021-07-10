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

#ifndef CRYPTO3_MARSHALLING_FIELD_ELEMENT_HPP
#define CRYPTO3_MARSHALLING_FIELD_ELEMENT_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>
#include <nil/marshalling/types/tag.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/marshalling/types/integral.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                template<typename TTypeBase, 
                         typename FieldType, 
                         typename = typename std::enable_if<
                            algebra::is_field<FieldType>::value, 
                            bool>::type,
                         typename... TOptions>
                using field_element = 
                    typename std::conditional<
                        algebra::is_extended_field<FieldType>::value,
                        nil::marshalling::types::array_list<
                            nil::marshalling::field_type<
                            nil::marshalling::option::little_endian>,
                            integral<
                                TTypeBase, 
                                typename FieldType::modulus_type>,
                            nil::marshalling::option::fixed_size_storage<
                                FieldType::arity>
                        >,
                        integral<
                            TTypeBase, 
                            typename FieldType::modulus_type
                        >
                    >::type;
                namespace detail {
                    template<typename FieldType>
                    typename std::enable_if<
                                !(algebra::is_extended_field<FieldType>::value), 
                                std::array<typename FieldType::modulus_type, 
                                    FieldType::arity>>::type
                        obtain_field_data(typename FieldType::value_type field_elem){

                        std::array<typename FieldType::modulus_type, 
                                    FieldType::arity> result;
                        result[0] = typename FieldType::modulus_type(field_elem.data);
                        return result;
                    }

                    template<typename FieldType>
                    typename std::enable_if<
                                algebra::is_extended_field<FieldType>::value, 
                                std::array<typename FieldType::modulus_type, 
                                    FieldType::arity>>::type
                        obtain_field_data(typename FieldType::value_type field_elem){
                        
                        std::array<typename FieldType::modulus_type, 
                                    FieldType::arity> result;

                        for (std::size_t i = 0; 
                             i < FieldType::arity/
                                FieldType::underlying_field_type::arity;
                             i++){
                            std::array<typename FieldType::modulus_type, 
                                FieldType::underlying_field_type::arity> 
                                intermediate_res = 
                                obtain_field_data<
                                typename FieldType::underlying_field_type>(
                                    field_elem.data[i]);
                            std::copy(intermediate_res.begin(), 
                                      intermediate_res.end(),
                                      result.begin() + 
                                      i*FieldType::underlying_field_type::arity);
                        }

                        return result;
                    }
                }    // namespace detail

                template<typename FieldType, 
                         typename Endianness>
                typename std::enable_if<
                            algebra::is_field<FieldType>::value &&
                            algebra::is_extended_field<FieldType>::value, 
                            field_element<
                                nil::marshalling::field_type<
                                Endianness>,
                            FieldType>>::type
                    fill_field_element(typename FieldType::value_type field_elem){
                    using field_element_type = field_element<
                        nil::marshalling::field_type<
                        Endianness>,
                        FieldType>;
                    using integral_type = integral<
                        nil::marshalling::field_type<
                        Endianness>,
                        typename FieldType::modulus_type>;

                    nil::marshalling::container::static_vector<
                        integral_type, FieldType::arity> container_data;
                    std::array<typename FieldType::modulus_type, 
                        FieldType::arity> val_container = 
                        detail::obtain_field_data<FieldType>(field_elem);
                    for (std::size_t i=0;
                         i < FieldType::arity;
                         i++){
                        container_data.push_back(integral_type(val_container[i]));
                    }
                    
                    return field_element_type(container_data);
                }

                template<typename FieldType, 
                         typename Endianness>
                typename std::enable_if<
                            algebra::is_field<FieldType>::value &&
                            !(algebra::is_extended_field<FieldType>::value), 
                            field_element<
                                nil::marshalling::field_type<
                                Endianness>,
                            FieldType>>::type
                    fill_field_element(typename FieldType::value_type field_elem){
                    using field_element_type = field_element<
                        nil::marshalling::field_type<
                        Endianness>,
                        FieldType>;
                    using integral_type = integral<
                        nil::marshalling::field_type<
                        Endianness>,
                        typename FieldType::modulus_type>;

                    return field_element_type(integral_type(
                        typename FieldType::modulus_type(field_elem.data)));
                }

            }    // namespace types
        }        // namespace marshalling
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_FIELD_ELEMENT_HPP

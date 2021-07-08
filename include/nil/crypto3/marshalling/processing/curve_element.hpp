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

#ifndef CRYPTO3_MARSHALLING_PROCESSING_CURVE_ELEMENT_HPP
#define CRYPTO3_MARSHALLING_PROCESSING_CURVE_ELEMENT_HPP

#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <limits>
#include <iterator>

#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/marshalling/processing/integral.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace processing {

                template<std::size_t TSize,
                         typename G2GroupElement, 
                         typename UnitIter, 
                         std::size_t UnitsCount,
                         typename Endianness>
                typename std::enable_if<detail::is_g2_group_element<G1GroupElement>::value, 
                    void>::type
                    write_data(const G2GroupElement &point, 
                               TIter &iter) {

                    constexpr static const std::size_t sizeof_field_element = 
                        TSize/(G2GroupElement::underlying_field_type::arity);
                    constexpr static const std::size_t units_bits = 8;
                    constexpr static const std::size_t chunk_bits = sizeof(typename TIter::value_type) * units_bits;
                    constexpr static const std::size_t sizeof_field_element_chunks_count = 
                        (sizeof_field_element / chunk_bits) + 
                        ((sizeof_field_element % chunk_bits)?1:0);

                    G2GroupElement point_affine = point.to_affine();
                    auto m_unit = detail::evaluate_m_unit(point_affine, true);
                    // TODO: check possibilities for TA

                    if (!(I_bit & m_unit)) {

                        Iter write_iter = iter;
                        // We assume here, that write_data doesn't change the iter
                        write_data<TSize, Endianness>(
                            point_affine.X.data[0].data.template convert_to<modulus_type>(), 
                            write_iter);

                        write_iter += sizeof_field_element_chunks_count;
                        // We assume here, that write_data doesn't change the iter
                        write_data<TSize, Endianness>(
                            point_affine.X.data[1].data.template convert_to<modulus_type>(), 
                            write_iter);

                    }
                    (*iter) |= m_unit;
                }

                template<std::size_t TSize,
                         typename G1GroupElement, 
                         typename UnitIter, 
                         std::size_t UnitsCount,
                         typename Endianness>
                typename std::enable_if<detail::is_g1_group_element<G1GroupElement>::value, 
                    void>::type
                    write_data(const G1GroupElement &point, 
                               TIter &iter) {

                    G1GroupElement point_affine = point.to_affine();
                    auto m_unit = detail::evaluate_m_unit(point_affine, true);
                    // TODO: check possibilities for TA

                    if (!(I_bit & m_unit)) {

                        // We assume here, that write_data doesn't change the iter
                        write_data<TSize, Endianness>(
                            point_affine.X.data.template convert_to<modulus_type>(), 
                            iter);
                    }
                    (*iter) |= m_unit;
                }

            }    // namespace processing
        }    // namespace marshalling
    }    // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_PROCESSING_CURVE_ELEMENT_HPP

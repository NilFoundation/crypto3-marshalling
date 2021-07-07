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
                namespace detail {

                    template<typename G1GroupElement, 
                             typename UnitIter, 
                             std::size_t UnitsCount>
                    typename std::enable_if<is_g1_group_element<G1GroupElement>::value, 
                        compressed_g1_octets>::type
                        point_to_units_compress(const G1GroupElement &point) {

                        compressed_g1_octets result = {0};
                        G1GroupElement point_affine = point.to_affine();
                        auto m_byte = evaluate_m_byte(point_affine, true);
                        // TODO: check possibilities for TA
                        if (!(I_bit & m_byte)) {
                            multiprecision::export_bits(
                                point_affine.X.data.template convert_to<modulus_type>(), result.rbegin(), 8, false);
                        }
                        result[0] |= m_byte;
                        return result;
                    }

                    template<typename G2GroupElement, 
                             typename UnitIter, 
                             std::size_t UnitsCount>
                    typename std::enable_if<is_g2_group_element<G2GroupElement>::value, 
                        compressed_g2_octets>::type
                        point_to_octets_compress(const G2GroupElement &point) {

                        compressed_g2_octets result = {0};
                        G2GroupElement point_affine = point.to_affine();
                        auto m_byte = evaluate_m_byte(point_affine, true);
                        // TODO: check possibilities for TA
                        if (!(I_bit & m_byte)) {
                            multiprecision::export_bits(
                                point_affine.X.data[0].data.template convert_to<modulus_type>(), result.rbegin(), 8, false);
                            multiprecision::export_bits(point_affine.X.data[1].data.template convert_to<modulus_type>(),
                                                        result.rbegin() + sizeof_field_element,
                                                        8,
                                                        false);
                        }
                        result[0] |= m_byte;
                        return result;
                    }

                    template<
                        typename G1GroupElement,
                        typename PointOctetsRange,
                        typename = typename std::enable_if<
                            std::is_same<std::uint8_t, typename PointOctetsRange::value_type>::value>::type>
                    typename std::enable_if<is_g1_group_element<G1GroupElement>::value, G1GroupElement>::type
                        compressed_to_point(PointOctetsRange &point_octets, std::uint8_t m_byte) {

                        using g1_value_type = G1GroupElement;
                        using g1_field_value_type = 
                            typename g1_value_type::underlying_field_value_type;

                        BOOST_ASSERT(std::distance(point_octets.begin(), point_octets.end()) == sizeof_field_element);

                        if (m_byte & I_bit) {
                            BOOST_ASSERT(point_octets.end() == std::find(point_octets.begin(), point_octets.end(), true));
                            return g1_value_type();    // point at infinity
                        }

                        modulus_type x;
                        multiprecision::import_bits(x, point_octets.rbegin(), point_octets.rend(), 8, false);
                        g1_field_value_type x_mod(x);
                        g1_field_value_type y2_mod = x_mod.pow(3) + g1_field_value_type(4);
                        BOOST_ASSERT(y2_mod.is_square());
                        g1_field_value_type y_mod = y2_mod.sqrt();
                        bool Y_bit = sign_gf_p(y_mod);
                        if (Y_bit == bool(m_byte & S_bit)) {
                            g1_value_type result(x_mod, y_mod, g1_field_value_type::one());
                            BOOST_ASSERT(result.is_well_formed());
                            return result;
                        }
                        g1_value_type result(x_mod, -y_mod, g1_field_value_type::one());
                        BOOST_ASSERT(result.is_well_formed());
                        return result;
                    }

                    template<
                        typename G2GroupElement,
                        typename PointOctetsRange,
                        typename = typename std::enable_if<
                             std::is_same<std::uint8_t, typename PointOctetsRange::value_type>::value>::type>
                    typename std::enable_if<is_g2_group_element<G2GroupElement>::value, G2GroupElement>::type
                        compressed_to_point(PointOctetsRange &point_octets, std::uint8_t m_byte) {

                        using g2_value_type = G2GroupElement;
                        using g2_field_value_type = 
                            typename g2_value_type::underlying_field_value_type;
                        BOOST_ASSERT(std::distance(point_octets.begin(), point_octets.end()) == 2 * sizeof_field_element);

                        if (m_byte & I_bit) {
                            BOOST_ASSERT(point_octets.end() == std::find(point_octets.begin(), point_octets.end(), true));
                            return g2_value_type();    // point at infinity
                        }

                        modulus_type x_0, x_1;
                        multiprecision::import_bits(
                            x_0, point_octets.rbegin(), point_octets.rbegin() + sizeof_field_element, 8, false);
                        multiprecision::import_bits(
                            x_1, point_octets.rbegin() + sizeof_field_element, point_octets.rend(), 8, false);
                        g2_field_value_type x_mod(x_0, x_1);
                        g2_field_value_type y2_mod = x_mod.pow(3) + g2_field_value_type(4, 4);
                        BOOST_ASSERT(y2_mod.is_square());
                        g2_field_value_type y_mod = y2_mod.sqrt();
                        bool Y_bit = sign_gf_p(y_mod);
                        if (Y_bit == bool(m_byte & S_bit)) {
                            g2_value_type result(x_mod, y_mod, g2_field_value_type::one());
                            BOOST_ASSERT(result.is_well_formed());
                            return result;
                        }
                        g2_value_type result(x_mod, -y_mod, g2_field_value_type::one());
                        BOOST_ASSERT(result.is_well_formed());
                        return result;
                    }

                    template<typename GroupValueType>
                    static inline std::uint8_t evaluate_m_byte(const GroupValueType &point, bool compression) {
                        std::uint8_t result = 0;
                        if (compression) {
                            result |= C_bit;
                        }
                        // TODO: check condition of infinite point
                        if (point.Z.is_zero()) {
                            result |= I_bit;
                        } else if (compression && sign_gf_p(point.Y)) {
                            result |= S_bit;
                        }
                        return result;
                    }

                    template<typename G1FieldElement>
                    typename std::enable_if<is_g1_field_element<G1FieldElement>::value, bool>::type
                        sign_gf_p(const G1FieldElement &v) {

                        constexpr static const typename G1FieldElement::modulus_type half_p =
                            (G1FieldElement::modulus - modulus_type(1)) / modulus_type(2);

                        if (v > half_p) {
                            return true;
                        }
                        return false;
                    }

                    template<typename G2FieldElement>
                    typename std::enable_if<is_g2_field_element<G2FieldElement>::value, bool>::type
                    static inline bool sign_gf_p(const g2_field_value_type &v) {
                        if (v.data[1] == 0) {
                            return sign_gf_p(v.data[0]);
                        }
                        return sign_gf_p(v.data[1]);
                    }

                }    // namespace detail
            }    // namespace processing
        }    // namespace marshalling
    }    // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_PROCESSING_CURVE_ELEMENT_HPP

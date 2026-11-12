#pragma once
#include <boost/multiprecision/cpp_int.hpp>
#include "Errors.h"
#include <cstdint>
#include <vector>


using type_8 = std::uint8_t;
using type_64 = std::uint64_t;
using big_type = boost::multiprecision::cpp_int;
using BigPolynomial = std::vector<big_type>;    // от младшей к старшей


template <typename T>
struct DivisionResult {
    T q;
    T r;
};

template <typename T>
struct ExtendedGcdResult {
    T gcd;
    T x;
    T y;
};

class PolynomialArithmetic {
private:
    template <typename T>
    static std::size_t GetDegree(T polynomial) {
        std::size_t count = 0;
        while (polynomial != 0) {
            polynomial >>= 1;
            count ++;
        }
        return count - 1;
    }

    template <typename T>
    static DivisionResult<T> DividePolynomial(T a, T b) {
        if (b == 0) throw Error::ERROR_DIVIDE_0;
        T q = 0;
        T r = a;
        std::size_t degreeB = GetDegree(b);
        while (r != 0 && GetDegree(r) >= degreeB) {
            std::size_t d = GetDegree(r) - degreeB;
            q ^= T(1) << d;
            r ^= b << d;
        }
        return {q, r};
    }

    template <typename T>
    static ExtendedGcdResult<T> ExtendedEuclideanGcd(T a, T b) {
        T oldR = a;
        T r = b;
        T oldX = 1;
        T x = 0;
        T oldY = 0;
        T y = 1;

        while (r != 0) {
            DivisionResult<T> division = DividePolynomial(oldR, r);
            T q = division.q;
            T temp = division.r;

            oldR = r;
            r = temp;

            temp = oldX ^ MultiplyFullPolynomials(q, x);
            oldX = x;
            x = temp;

            temp = oldY ^ MultiplyFullPolynomials(q, y);
            oldY = y;
            y = temp;
        }

        return {oldR, oldX, oldY};
    }

    template <typename T>
    static T MultiplyFullPolynomials(T a, T b) {
        T result = 0;

        while (b != 0) {
            if (b & 1) result ^= a;
            a <<= 1;
            b >>= 1;
        }

        return result;
    }

    template <typename T>
    static std::vector<T> GenerateIrreduciblePolynomials(std::size_t maxDegree) {
        std::vector<T> irreduciblePolynomials;

        for (std::size_t i = 1; i <= maxDegree; i++) {
            T start = T(1) << i;
            T end = (T(1) << (i + 1)) - 1;

            for (T polynomial = start; polynomial <= end; polynomial++) {
                bool isIrreducible = true;

                for (const T& divisor : irreduciblePolynomials) {
                    if (GetDegree(divisor) > i / 2) break;

                    if (DividePolynomial(polynomial, divisor).r == 0) {
                        isIrreducible = false;
                        break;
                    }
                }

                if (isIrreducible) irreduciblePolynomials.push_back(polynomial);
            }
        }

        return irreduciblePolynomials;
    }

    template <typename T>
    static bool IsFieldModulusIrreducible(T polynomial) {
        if (polynomial <= 0 || GetDegree(polynomial) == 0) return false;
        std::size_t degree = GetDegree(polynomial);
        std::vector<T> divisors = GenerateIrreduciblePolynomials<T>(degree / 2);
        for (std::size_t i = 0; i < divisors.size(); i++) {
            if (DividePolynomial(polynomial, divisors[i]).r == 0) return false;
        }
        return true;
    }

    static big_type MultiplyFieldElements(big_type a, big_type b, big_type fieldModulus);
    static big_type InverseFieldElement(big_type a, big_type fieldModulus);
    static DivisionResult<BigPolynomial> DivideFieldPolynomials(BigPolynomial a, BigPolynomial b, big_type fieldModulus);
public:
    static type_8 AddPolynomial ( type_8  a, type_8 b);
    static type_8 MultiplyPolynomial ( type_8  a, type_8 b, type_8 mod);
    static type_8 InversePolynomial( type_8  a, type_8 mod);
    static bool IsIrreducible( type_8  polynomial);
    static std::vector< type_8 > GenerateAllIrreduciblePolynomials();
    static std::vector<BigPolynomial> FactorizePolynomial(big_type polynomial, big_type fieldModulus);
};

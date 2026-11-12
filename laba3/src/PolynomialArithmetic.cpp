#include "PolynomialArithmetic.h"

big_type PolynomialArithmetic::MultiplyFieldElements(big_type a, big_type b, big_type fieldModulus) {
    std::size_t n = GetDegree(fieldModulus);
    big_type result = 0;
    while (b != 0) {
        if (b & 1) result ^= a;
        bool carry = (a & (big_type(1) << (n - 1))) != 0;
        a <<= 1;
        if (carry) a ^= fieldModulus;
        b >>= 1;
    }
    return result;
}

big_type PolynomialArithmetic::InverseFieldElement(big_type a, big_type fieldModulus) {
    if (a == 0) throw Error::ERROR_ZERO_HAS_NO_INVERSE;

    ExtendedGcdResult<big_type> result = ExtendedEuclideanGcd(a, fieldModulus);

    if (result.gcd != 1) throw Error::ERROR_NO_INVERSE;

    return DividePolynomial(result.x, fieldModulus).r;
}

DivisionResult<BigPolynomial> PolynomialArithmetic::DivideFieldPolynomials(BigPolynomial a, BigPolynomial b, big_type fieldModulus) {
    if (a.empty()) a.push_back(0);
    if (b.empty()) b.push_back(0);
    while (a.size() > 1 && a.back() == 0) a.pop_back();
    while (b.size() > 1 && b.back() == 0) b.pop_back();
    if (b.size() == 1 && b[0] == 0) throw Error::ERROR_DIVIDE_0;
    BigPolynomial q(a.size(), 0);
    BigPolynomial r = a;
    while (!(r.size() == 1 && r[0] == 0) && r.size() >= b.size()) {
        std::size_t d = r.size() - b.size();
        big_type coefficient = MultiplyFieldElements(r.back(), InverseFieldElement(b.back(), fieldModulus), fieldModulus);
        q[d] ^= coefficient;
        for (std::size_t i = 0; i < b.size(); i++) {
            r[i + d] ^= MultiplyFieldElements(coefficient, b[i], fieldModulus);
        }
        while (r.size() > 1 && r.back() == 0) r.pop_back();
    }
    while (q.size() > 1 && q.back() == 0) q.pop_back();
    return {q, r};
}

type_8  PolynomialArithmetic::AddPolynomial(type_8 a, type_8 b) {
    return a ^ b;
}

type_8 PolynomialArithmetic::MultiplyPolynomial(type_8 a, type_8 b, type_8 mod) {
    if (!IsIrreducible(mod)) throw Error::ERROR_REDUCIBLE_MODULUS;
    type_8 result = 0;
    while (b != 0) {
        if (b & 1) result ^= a;
        bool carry = a & 0x80;  // 10000000
        a <<= 1;
        if (carry) a ^= mod;
        b >>= 1;
    }
    return result;
}

type_8 PolynomialArithmetic::InversePolynomial(type_8 a, type_8 mod){
    if (a == 0) throw Error::ERROR_ZERO_HAS_NO_INVERSE;
    if (!IsIrreducible(mod)) throw Error::ERROR_REDUCIBLE_MODULUS;
    type_64 fullMod = (type_64(1) << 8) | mod;  // 8 степень теперь записана единицей
    ExtendedGcdResult<type_64> result = ExtendedEuclideanGcd(static_cast<type_64>(a), fullMod);
    if (result.gcd != 1) throw Error::ERROR_NO_INVERSE;
    return DividePolynomial(result.x, fullMod).r;
}

bool PolynomialArithmetic::IsIrreducible(type_8 polynomial) {
    type_64 fullPolynomial = (type_64(1) << 8) | polynomial;
    std::vector<type_64> divisors = GenerateIrreduciblePolynomials<type_64>(4);
    for (int i = 0; i < divisors.size(); i++) {
        if (DividePolynomial(fullPolynomial, divisors[i]).r == 0) return false;
    }
    return true;
}

std::vector<type_8> PolynomialArithmetic::GenerateAllIrreduciblePolynomials() {
    std::vector<type_8> result;
    for (int i = 0; i <= 255; i++) {
        bool IsIrr = IsIrreducible(i);
        if (IsIrr) result.push_back(i);
    }
    return result;
}

std::vector<BigPolynomial> PolynomialArithmetic::FactorizePolynomial(big_type polynomial, big_type fieldModulus) {
    std::vector<BigPolynomial> result;
    if (polynomial < 0 || fieldModulus <= 0) throw Error::ERROR_INVALID_POLYNOMIAL;
    if (polynomial == 0) throw Error::ERROR_ZERO_POLYNOMIAL;
    if (!IsFieldModulusIrreducible(fieldModulus)) throw Error::ERROR_REDUCIBLE_MODULUS;
    if (polynomial == 1) return result;

    BigPolynomial coefficients;
    while (polynomial != 0) {
        coefficients.push_back(polynomial & 1);
        polynomial >>= 1;
    }

    std::size_t n = GetDegree(fieldModulus);
    big_type elements = big_type(1) << n;
    std::vector<BigPolynomial> polynomialsToFactor;
    polynomialsToFactor.push_back(coefficients);

    while (!polynomialsToFactor.empty()) {
        BigPolynomial currentPolynomial = polynomialsToFactor.back();
        polynomialsToFactor.pop_back();
        std::size_t degree = currentPolynomial.size() - 1;
        bool found = false; // есть делитель или нет
        for (std::size_t divisorDegree = 1; divisorDegree <= degree / 2; divisorDegree++) {
            big_type combinations = 1;
            for (std::size_t i = 0; i < divisorDegree; i++) combinations *= elements;
            for (big_type combination = 0; combination < combinations; combination++) {
                big_type temp = combination;
                BigPolynomial divisor(divisorDegree + 1, 0);
                for (std::size_t i = 0; i < divisorDegree; i++) {
                    divisor[i] = temp % elements;
                    temp /= elements;
                }
                divisor[divisorDegree] = 1;
                auto division = DivideFieldPolynomials(currentPolynomial, divisor, fieldModulus);
                if (division.r.size() == 1 && division.r[0] == 0) {
                    polynomialsToFactor.push_back(divisor);
                    polynomialsToFactor.push_back(division.q);
                    found = true;
                    break;
                }
            }
            if (found) break;
        }
        if (!found) result.push_back(currentPolynomial);
    }
    return result;
}
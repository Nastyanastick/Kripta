
#include "PolynomialArithmetic.h"
#include <iostream>
#include <vector>
#include <algorithm>

int passed = 0;
int failed = 0;

void check(const std::string& name, bool result) {
    if (result) {
        std::cout << "[PASS] " << name << '\n';
        passed++;
    }
    else {
        std::cout << "[FAIL] " << name << '\n';
        failed++;
    }
}

template <typename Function>
void checkThrows(const std::string& name, Function function) {
    try {
        function();
        check(name, false);
    }
    catch (Error error) {
        check(name, true);
    }
    catch (...) {
        check(name, false);
    }
}

// Сравнение факторизаций без учёта порядка множителей
bool SameFactors(std::vector<BigPolynomial> actual, std::vector<BigPolynomial> expected) {
    if (actual.size() != expected.size()) return false;

    for (const BigPolynomial& factor : expected) {
        auto it = std::find(actual.begin(), actual.end(), factor);

        if (it == actual.end()) return false;

        actual.erase(it);
    }

    return actual.empty();
}

void testAddition() {
    std::cout << "\n1. ADDITION GF(2^8)\n";

    check("0x57 + 0x83 = 0xD4",
        PolynomialArithmetic::AddPolynomial(0x57, 0x83) == 0xD4);

    check("0x00 + 0x00 = 0x00",
        PolynomialArithmetic::AddPolynomial(0x00, 0x00) == 0x00);

    check("0xFF + 0xFF = 0x00",
        PolynomialArithmetic::AddPolynomial(0xFF, 0xFF) == 0x00);
}

void testMultiplication() {
    std::cout << "\n2. MULTIPLICATION GF(2^8)\n";

    check("0x57 * 0x83 = 0xC1",
        PolynomialArithmetic::MultiplyPolynomial(0x57, 0x83, 0x1B) == 0xC1);

    check("Multiplication by zero",
        PolynomialArithmetic::MultiplyPolynomial(0x53, 0x00, 0x1B) == 0x00);

    check("Multiplication by one",
        PolynomialArithmetic::MultiplyPolynomial(0x53, 0x01, 0x1B) == 0x53);

    check("0x80 * 0x02 = 0x1B",
        PolynomialArithmetic::MultiplyPolynomial(0x80, 0x02, 0x1B) == 0x1B);
}

void testInverse() {
    std::cout << "\n3. INVERSE GF(2^8)\n";

    type inverse = PolynomialArithmetic::InversePolynomial(0x53, 0x1B);

    check("Inverse of 0x53 = 0xCA", inverse == 0xCA);

    check("0x53 * inverse(0x53) = 1",
        PolynomialArithmetic::MultiplyPolynomial(0x53, inverse, 0x1B) == 1);

    check("Inverse of 0x01 = 0x01",
        PolynomialArithmetic::InversePolynomial(0x01, 0x1B) == 0x01);

    checkThrows("Zero has no inverse", []() {
        PolynomialArithmetic::InversePolynomial(0x00, 0x1B);
    });
}

void testIrreducibility() {
    std::cout << "\n4. IRREDUCIBILITY CHECK\n";

    check("0x1B is irreducible",
        PolynomialArithmetic::IsIrreducible(0x1B));

    check("0x1D is irreducible",
        PolynomialArithmetic::IsIrreducible(0x1D));

    check("0x01 is reducible",
        !PolynomialArithmetic::IsIrreducible(0x01));

    check("0x00 is reducible",
        !PolynomialArithmetic::IsIrreducible(0x00));
}

void testGenerateIrreduciblePolynomials() {
    std::cout << "\n5. ALL IRREDUCIBLE POLYNOMIALS\n";

    std::vector<type> actual =
        PolynomialArithmetic::GenerateAllIrreduciblePolynomials();

    std::vector<type> expected = {
        0x1B, 0x1D, 0x2B, 0x2D, 0x39, 0x3F,
        0x4D, 0x5F, 0x63, 0x65, 0x69, 0x71,
        0x77, 0x7B, 0x87, 0x8B, 0x8D, 0x9F,
        0xA3, 0xA9, 0xB1, 0xBD, 0xC3, 0xCF,
        0xD7, 0xDD, 0xE7, 0xF3, 0xF5, 0xF9
    };

    check("Exactly 30 irreducible polynomials", actual.size() == 30);
    check("All generated polynomials match expected values", actual == expected);
}

void testFactorization() {
    std::cout << "\n6. POLYNOMIAL FACTORIZATION\n";

    // x^2 + x + 1 over GF(4)
    check("Factorization of x^2 + x + 1",
        SameFactors(
            PolynomialArithmetic::FactorizePolynomial(0b111, 0b111),
            { {2, 1}, {3, 1} }
        )
    );

    // x^2 + 1 = (x + 1)^2 over GF(4)
    check("Factorization of x^2 + 1",
        SameFactors(
            PolynomialArithmetic::FactorizePolynomial(0b101, 0b111),
            { {1, 1}, {1, 1} }
        )
    );

    // x
    check("Factorization of x",
        SameFactors(
            PolynomialArithmetic::FactorizePolynomial(0b10, 0b111),
            { {0, 1} }
        )
    );

    // 1 has no irreducible factors
    check("Factorization of 1",
        PolynomialArithmetic::FactorizePolynomial(0b1, 0b111).empty()
    );

    checkThrows("Zero polynomial cannot be factorized", []() {
        PolynomialArithmetic::FactorizePolynomial(0, 0b111);
    });

    checkThrows("Reducible field modulus is rejected", []() {
        PolynomialArithmetic::FactorizePolynomial(0b111, 0b101);
    });
}

void testExceptions() {
    std::cout << "\n7. EXCEPTION CHECKS\n";

    checkThrows("Multiplication with reducible modulus", []() {
        PolynomialArithmetic::MultiplyPolynomial(0x57, 0x83, 0x01);
    });

    checkThrows("Inverse with reducible modulus", []() {
        PolynomialArithmetic::InversePolynomial(0x53, 0x01);
    });
}

int main() {
    testAddition();
    testMultiplication();
    testInverse();
    testIrreducibility();
    testGenerateIrreduciblePolynomials();
    testFactorization();
    testExceptions();

    std::cout << "\n================================\n";
    std::cout << "PASSED: " << passed << '\n';
    std::cout << "FAILED: " << failed << '\n';
    std::cout << "TOTAL:  " << passed + failed << '\n';
    std::cout << "================================\n";

    return failed == 0 ? 0 : 1;
}

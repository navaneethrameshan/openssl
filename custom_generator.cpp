#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecerr.h>
#include <openssl/err.h>
#include <openssl/ecdh.h>
#include <iostream>
#include <chrono>
#include <ec/ec_lcl.h>
#include <cstring>



int hexdump(unsigned char* lpValue, unsigned long lValueLen) {
  if (lpValue) {
    printf("\tLength: %lu Bytes", lValueLen);
    printf("\tValue: ");

    int lPrintedBytes = 0;
    unsigned long i = 0;
    for (i = 0; i < lValueLen; i++) {
      lPrintedBytes++;
      printf("%02x", lpValue[i]);
    }
    return 1;
  }
  else
    return 0;

}

int printBigNumAsHEX(BIGNUM *InputNumber, bool WithNewLine = true)
{
  if(InputNumber) {
    auto *temp = (unsigned char *) malloc(BN_num_bytes(InputNumber));
    BN_bn2bin(InputNumber, temp);
    hexdump(temp, BN_num_bytes(InputNumber));
    return 1;
  }
  else
    return 0;
}

int main(){
  using namespace std;

  // EC curve to be used
  int CurveID = NID_X9_62_prime256v1;

  // Prepare a BigNum context
  BN_CTX *BN_context = NULL;
  BN_context = BN_CTX_secure_new();
  // Prepare the EC Group
  EC_GROUP *Test_ECC_Group = EC_GROUP_new_by_curve_name(CurveID);
  EC_POINT *Custom_Generator = EC_POINT_new(Test_ECC_Group);
  // Prepare the output point
  EC_POINT *Test_Point_Result = EC_POINT_new(Test_ECC_Group);
  EC_POINT *Test_Point_Result2 = EC_POINT_new(Test_ECC_Group);
  EC_POINT *Test_Point_Result3 = EC_POINT_new(Test_ECC_Group);

  // Prepare a random EC point (which will be the custom generator)
  BIGNUM *PointRandomizer = NULL; PointRandomizer = BN_secure_new();
  BIGNUM *CurveOrder = NULL; CurveOrder = BN_secure_new();
  EC_GROUP_get_order(Test_ECC_Group, CurveOrder, BN_context);
  BN_rand_range(PointRandomizer, CurveOrder);

  // Prepare a random scalar
  BIGNUM *RandomNumber = NULL;
  RandomNumber = BN_secure_new();
  BN_rand_range(RandomNumber, CurveOrder);
  int errorcount = 0;

  { //---------------------------------------------------------------------------
    // Precomputed version of default generator point multiplication
    // Start the timer
    auto start = std::chrono::high_resolution_clock::now();
    errorcount = 0;
    for (int i = 0; i < 10000; i++) // run the same test 10000 times to get a reasonable average timing
    {
      // Point multiplication
      if (!EC_POINT_mul(Test_ECC_Group,
                        Test_Point_Result,
                        RandomNumber,
                        NULL,
                        NULL,
                        BN_context))
        errorcount++;
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << std::endl << "\n Default Generator point multiplication (precomputation ACTIVE): ";
    std::cout << std::endl << "Number of errors: " << errorcount;
    EC_POINT_make_affine(Test_ECC_Group, Test_Point_Result, BN_context);
    std::cout << std::endl << "X: ";
    printBigNumAsHEX(Test_Point_Result->X, false);
    std::cout << std::endl << "Y: ";
    printBigNumAsHEX(Test_Point_Result->Y, false);
    // Process the timing and display the result
    chrono::duration<double> elapsed_seconds = end - start;
    std::cout << std::endl << "Duration of an EC point multiplication [us]: "
              << elapsed_seconds.count() * 1.0e6 / 10000.0;

  }
  //---------------------------------------------------------------------------
  // Now we run the test with a new (random) point as the generator. Hence we change the generator point
  //Multiply the default generator with a random value to get the custom generator
  EC_POINT_mul(Test_ECC_Group, Custom_Generator, PointRandomizer, NULL, NULL, BN_context);

  const BIGNUM *GroupOrderTest = NULL; GroupOrderTest = BN_secure_new(); GroupOrderTest = EC_GROUP_get0_order(Test_ECC_Group);
  const BIGNUM *Cofactor = NULL; Cofactor = BN_secure_new(); Cofactor = EC_GROUP_get0_cofactor(Test_ECC_Group);
  if (EC_POINT_is_on_curve(Test_ECC_Group, Custom_Generator, BN_context))
    std::cout << std::endl << "\n-->Custom generator is on curve";
  else
    std::cout << std::endl << "\n------------------->Custom generator is not on curve";


  //Set custom generator
  if (1 != EC_GROUP_set_generator(Test_ECC_Group, Custom_Generator, GroupOrderTest, Cofactor))
    std::cout << std::endl << "\nError in setting generator";
  else
    std::cout<<"\nSuccessfully set custom generator for the curve ...";


  //---------------------------------------------------------------------------
  // Modified generator point multiplication (precomputation NOT active)
  {
    auto start = std::chrono::high_resolution_clock::now();
    errorcount = 0;
    for (int i = 0; i < 10000; i++) // run the same test 10000 times to get a reasonable average timing
    {
      // Generator multiplication
      if (!EC_POINT_mul(Test_ECC_Group, Test_Point_Result2, RandomNumber, NULL, NULL,
                        BN_context))
        errorcount++;

    }
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << std::endl << "\nModified generator point multiplication (precomputation NOT active): ";
    std::cout << std::endl << "Number of errors: " << errorcount;
    EC_POINT_make_affine(Test_ECC_Group, Test_Point_Result2, BN_context);
    std::cout << std::endl << "X: ";
    printBigNumAsHEX(Test_Point_Result2->X, false);
    std::cout << std::endl << "Y: ";
    printBigNumAsHEX(Test_Point_Result2->Y, false);
    // Process the timing and display the result
    chrono::duration<double> elapsed_seconds = end - start;
    std::cout << std::endl << "Duration of an EC point multiplication [us]: "
              << elapsed_seconds.count() * 1.0e6 / 10000.0;
  }
  //---------------------------------------------------------------------------
  // Modified generator point multiplication (precomputation ACTIVE)
  {
    //Precompute!
    if (1 != EC_GROUP_precompute_mult(Test_ECC_Group, BN_context))
      std::cout << std::endl << "\nERROR in precomputation!";
    if (Test_ECC_Group->pre_comp.nistz256)
      std::cout << std::endl << "\nPrecomputation table is now available";


    // Start the timer
    auto start = std::chrono::high_resolution_clock::now();
    errorcount = 0;
    for (int i = 0; i < 10000; i++) // run the same test 10000 times to get a reasonable average timing
    {
      // Generator multiplication
      if (!EC_POINT_mul(Test_ECC_Group, Test_Point_Result3, RandomNumber, NULL, NULL, BN_context))
        errorcount++;

    }
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << std::endl << "\nModified generator point multiplication (precomputation ACTIVE): ";
    std::cout << std::endl << "Number of errors: " << errorcount;
    EC_POINT_make_affine(Test_ECC_Group, Test_Point_Result3, BN_context);
    std::cout << std::endl << "X: ";
    printBigNumAsHEX(Test_Point_Result3->X, false);
    std::cout << std::endl << "Y: ";
    printBigNumAsHEX(Test_Point_Result3->Y, false);
    // Process the timing and display the result
    chrono::duration<double> elapsed_seconds = end - start;
    std::cout << std::endl << "Duration of an EC point multiplication [us]: "
              << elapsed_seconds.count() * 1.0e6 / 10000.0;
  }

  //clean up
  EC_POINT_free(Custom_Generator);
  EC_POINT_free(Test_Point_Result);
  EC_POINT_free(Test_Point_Result2);
  EC_POINT_free(Test_Point_Result3);
  BN_free(PointRandomizer);
  BN_free(CurveOrder);
  BN_free(RandomNumber);
  BN_free(const_cast<BIGNUM *>(GroupOrderTest));
  BN_free(const_cast<BIGNUM *>(Cofactor));
  BN_CTX_free(BN_context);


  return 0;
}
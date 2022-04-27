/** @file
 *****************************************************************************

 Implementation of functionality that runs the R1CS GG-ppzkSNARK for
 a given R1CS example.

 See run_r1cs_gg_ppzksnark.hpp .

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef RUN_R1CS_GG_PPZKSNARK_TCC_
#define RUN_R1CS_GG_PPZKSNARK_TCC_

#include <sstream>
#include <type_traits>

#include <libff/common/profiling.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

namespace libsnark {

template<typename ppT>
typename std::enable_if<ppT::has_affine_pairing, void>::type
test_affine_verifier(const r1cs_gg_ppzksnark_verification_key<ppT> &vk,
                     const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input,
                     const r1cs_gg_ppzksnark_proof<ppT> &proof,
                     const bool expected_answer)
{
    libff::print_header("R1CS GG-ppzkSNARK Affine Verifier");
    const bool answer = r1cs_gg_ppzksnark_affine_verifier_weak_IC<ppT>(vk, primary_input, proof);
    assert(answer == expected_answer);
}

template<typename ppT>
typename std::enable_if<!ppT::has_affine_pairing, void>::type
test_affine_verifier(const r1cs_gg_ppzksnark_verification_key<ppT> &vk,
                     const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input,
                     const r1cs_gg_ppzksnark_proof<ppT> &proof,
                     const bool expected_answer)
{
    libff::print_header("R1CS GG-ppzkSNARK Affine Verifier");
    libff::UNUSED(vk, primary_input, proof, expected_answer);
    printf("Affine verifier is not supported; not testing anything.\n");
}

/**
 * The code below provides an example of all stages of running a R1CS GG-ppzkSNARK.
 *
 * Of course, in a real-life scenario, we would have three distinct entities,
 * mangled into one in the demonstration below. The three entities are as follows.
 * (1) The "generator", which runs the ppzkSNARK generator on input a given
 *     constraint system CS to create a proving and a verification key for CS.
 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
 *     a primary input for CS, and an auxiliary input for CS.
 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
 *     a primary input for CS, and a proof.
 */
template<typename ppT>
bool run_r1cs_gg_ppzksnark(const r1cs_example<libff::Fr<ppT> > &example,
                        const bool test_serialization)
{
    libff::enter_block("Call to run_r1cs_gg_ppzksnark");

    libff::print_header("R1CS GG-ppzkSNARK Generator");
    r1cs_gg_ppzksnark_keypair<ppT> keypair = r1cs_gg_ppzksnark_generator<ppT>(example.constraint_system);
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");

    libff::print_header("Preprocess verification key");
    r1cs_gg_ppzksnark_processed_verification_key<ppT> pvk = r1cs_gg_ppzksnark_verifier_process_vk<ppT>(keypair.vk);

    if (test_serialization)
    {
        libff::enter_block("Test serialization of keys");
        keypair.pk = libff::reserialize<r1cs_gg_ppzksnark_proving_key<ppT> >(keypair.pk);
        keypair.vk = libff::reserialize<r1cs_gg_ppzksnark_verification_key<ppT> >(keypair.vk);
        pvk = libff::reserialize<r1cs_gg_ppzksnark_processed_verification_key<ppT> >(pvk);
        libff::leave_block("Test serialization of keys");
    }

    libff::print_header("R1CS GG-ppzkSNARK Prover");
    r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(keypair.pk, example.primary_input, example.auxiliary_input);
    printf("\n"); libff::print_indent(); libff::print_mem("after prover");

    if (test_serialization)
    {
        libff::enter_block("Test serialization of proof");
        proof = libff::reserialize<r1cs_gg_ppzksnark_proof<ppT> >(proof);
        libff::leave_block("Test serialization of proof");
    }

    libff::print_header("R1CS GG-ppzkSNARK Verifier");
    const bool ans = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, example.primary_input, proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    libff::print_header("R1CS GG-ppzkSNARK Online Verifier");
    const bool ans2 = r1cs_gg_ppzksnark_online_verifier_strong_IC<ppT>(pvk, example.primary_input, proof);
    assert(ans == ans2);

    test_affine_verifier<ppT>(keypair.vk, example.primary_input, proof, ans);

    libff::leave_block("Call to run_r1cs_gg_ppzksnark");

    return ans;
}

template<typename ppT>
void generate_pk_vk(const r1cs_constraint_system<libff::Fr<ppT> > &cs, char *pk_path, char *vk_path)
{
    r1cs_gg_ppzksnark_keypair<ppT> keypair = r1cs_gg_ppzksnark_generator<ppT>(cs);
    std::ofstream pko(pk_path, ios::out);
    pko << keypair.pk;
    pko.close();
    std::ofstream vko(vk_path, ios::out);
    vko << keypair.vk;
    vko.close();
}

template<typename ppT>
void prove(const r1cs_constraint_system<libff::Fr<ppT> > &cs, char *proof_key_filename, char *primary_input_filename, char *aux_input_filename, char *output_proof_filename)
{
    std::cout << "enter prove" << std::endl;
    r1cs_gg_ppzksnark_proving_key<ppT> pk;
    std::ifstream pki(proof_key_filename, ios::in);
    pki >> pk;
    pki.close();
    std::cout << "finish loading pk" << std::endl;

    r1cs_primary_input<FieldT> primary_input, aux_input;
    std::ifstream pi(primary_input_filename, ios::binary | ios::in);
    pi >> primary_input;
    pi.close();

    std::ifstream ai(aux_input_filename, ios::binary | ios::in);
    ai >> aux_input;
    ai.close();

    r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(cs, pk, primary_input, aux_input);
    
    std::ofstream po(output_proof_filename, ios::binary | ios::out);
    po << proof;
    po.close();
}

template<typename ppT>
void convert(char *proof_key_filename, char * vkey_filename, char * primary_input_filename, char * proof_filename, char * output_vkey_filename, char * output_primary_input_filename, char * output_proof_filename)
{
    r1cs_gg_ppzksnark_proving_key<ppT> pk;
    std::ifstream pki(proof_key_filename, ios::in);
    pki >> pk;
    auto alpha = pk.alpha_g1;
    auto beta = pk.beta_g2;

    r1cs_gg_ppzksnark_verification_key<ppT> vk;
    std::ifstream vki(vkey_filename, ios::in);
    vki >> vk;
    vki.close();

    std::ofstream vko(output_vkey_filename, ios::out);
    alpha.marshal(vko);
    beta.marshal(vko);
    vk.delta_g2.marshal(vko);
    vk.gamma_g2.marshal(vko);
    vk.gamma_ABC_g1.first.marshal(vko);
    for (auto &i : vk.gamma_ABC_g1.rest.values) {
        i.marshal(vko);
    }
    vko.close();

    r1cs_gg_ppzksnark_proof<ppT> proof;
    std::ifstream  pi(proof_filename, ios::in);
    pi >> proof;
    pi.close();

    std::ofstream po(output_proof_filename, ios::binary | ios::out);
    proof.g_A.marshal(po);
    proof.g_B.marshal(po);
    proof.g_C.marshal(po);
    std::string po_filename(output_proof_filename);
    std::ofstream po_negA(po_filename + ".negA", ios::binary | ios::out);
    std::ofstream po_B(po_filename + ".B", ios::binary | ios::out);
    std::ofstream po_C(po_filename + ".C", ios::binary | ios::out);
    (-(proof.g_A)).marshal(po_negA);
    proof.g_B.marshal(po_B);
    proof.g_C.marshal(po_C);

    r1cs_primary_input<FieldT> primary_input;
    std::ifstream pii(primary_input_filename, ios::binary | ios::in);
    pii >> primary_input;

    // when field element fits in a uint_32, marshal that uint_32 in big endian
    std::ofstream opi(output_primary_input_filename, ios::binary | ios::out);
    for (auto &i : primary_input) {
        unsigned long tmp = i.as_ulong();
        uint32_t tmp2 = (uint32_t)tmp;
        uint8_t *p = (uint8_t *)&tmp2;
        for (int j = 3; j >= 0; j--) {
            opi << p[j];
        }
    }
}

template<typename ppT>
void verify(char *proof_filename, char *vkey_filename, char *primary_input_filename) {
    r1cs_gg_ppzksnark_proof<ppT> proof;
    std::ifstream  pi(proof_filename, ios::in);
    pi >> proof;
    pi.close();

    std::cout << "haaaaaaaaaaaaaaaaaaaa" << std::endl;
    proof.g_A.pt.x.dump();
    proof.g_A.pt.x.fromMont();
    proof.g_A.pt.x.dump();
    exit(0);

    r1cs_gg_ppzksnark_verification_key<ppT> vk;
    std::ifstream vki(vkey_filename, ios::in);
    vki >> vk;
    vki.close();

    r1cs_primary_input<FieldT> primary_input;
    std::ifstream pii(primary_input_filename, ios::binary | ios::in);
    pii >> primary_input;
    pii.close();

    libff::print_header("R1CS GG-ppzkSNARK Verifier");
    const bool ans = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(vk, primary_input, proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));
}


} // libsnark

#endif // RUN_R1CS_GG_PPZKSNARK_TCC_

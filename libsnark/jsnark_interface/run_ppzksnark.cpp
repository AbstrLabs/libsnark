/*
 * run_ppzksnark.cpp
 *
 *      Author: Ahmed Kosba
 */

#include "CircuitReader.hpp"
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/examples/run_r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <stdlib.h>
#include <fstream>

enum Command {
	TranslateCircuit,
	TranslateInput,
	Translate,
	Generate,
	Prove,
	Verify,
};

int main(int argc, char **argv) {

	libff::start_profiling();
	gadgetlib2::initPublicParamsFromDefaultPp();
	gadgetlib2::GadgetLibAdapter::resetVariableIndex();
	ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);
	Command cmd;

	int inputStartIndex = 0;
	assert(argc > 2);
	if (strcmp(argv[1], "translate_circuit") == 0) {
		cmd = TranslateCircuit;
	} else if (strcmp(argv[1], "translate_input") == 0) {
		cmd = TranslateInput;
	} else if (strcmp(argv[1], "translate") == 0) {
		cmd = Translate;
	} else if (strcmp(argv[1], "generate") == 0) {
		cmd = Generate;
	} else if (strcmp(argv[1], "prove") == 0) {
		cmd = Prove;
	} else if (strcmp(argv[1], "verify") == 0) {
		cmd = Verify;
	} else {
		cerr << "Unimplemented" << endl;
		exit(1);
	}

	cout << "Using ppzsknark in the generic group model [Groth16]." << endl;
	switch (cmd) {
	case TranslateCircuit:
	{		
		assert(argc == 5);
		char *arith_filename = argv[2];
		char *output_circuit_filename = argv[3];
		char *output_metadata_filename = argv[4];
		cout << "Translate Circuit" << endl;
		CircuitReader reader(arith_filename, pb);
		r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);
		std::ofstream cs_out(output_circuit_filename, ios::binary | ios::out);
		cs_out << cs;
		cs_out.close();
		std::ofstream m_out(output_metadata_filename, ios::out);
		m_out << cs.primary_input_size + cs.auxiliary_input_size << endl;
		// TODO: more metadata
		m_out.close();
		break;
	}
	case Translate:
	{
		// Translate Input seems challenging to write, as first step, use this translate circuit + translate input combination
		assert(argc == 7);
		char *arith_filename = argv[2];
		char *in_filename = argv[3];
		char *output_circuit_filename = argv[4];
		char *output_primary_input_filename = argv[5];
		char *output_auxiliary_input_filename = argv[6];
		cout << "Translate Circuit and Input" << endl;
		CircuitReader reader(arith_filename, in_filename, pb);
		r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);
		const r1cs_variable_assignment<FieldT> full_assignment = get_variable_assignment_from_gadgetlib2(*pb);
		cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
		cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();
		const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(),
			full_assignment.begin() + cs.num_inputs());
		const r1cs_auxiliary_input<FieldT> auxiliary_input(
			full_assignment.begin() + cs.num_inputs(), full_assignment.end());
		std::ofstream oc(output_circuit_filename, ios::binary | ios::out);
		oc << cs;
		oc.close();
		std::ofstream opi(output_primary_input_filename, ios::binary | ios::out);
		opi << primary_input;
		opi.close();
		std::ofstream oai(output_auxiliary_input_filename, ios::binary | ios::out);
		oai << auxiliary_input;
		oai.close();
		break;
	}
	case TranslateInput:
	{
		// assert(argc == 5);
		// char *in_filename = argv[2];
		// char *primary_input_filename = argv[3];
		// char *auxiliary_input_filename = argv[4];
		// cout << "Translate Input" << endl;
		// break;
	}
	case Generate:
	{
		assert(argc == 5);
		char *circuit_filename = argv[2];
		char *output_proof_key_filename = argv[3];
		char *output_vkey_filename = argv[4];
		r1cs_constraint_system<FieldT> cs;
		std::ifstream ci(circuit_filename, ios::binary | ios::in);
		ci >> cs;
		ci.close();
		libsnark::generate_pk_vk<libsnark::default_r1cs_gg_ppzksnark_pp>(cs, output_proof_key_filename, output_vkey_filename);
		break;
	}
	case Prove:
	{
		assert(argc == 7);
		char *circuit_filename = argv[2];
		char *proof_key_filename = argv[3];
		char *primary_input_filename = argv[4];
		char *aux_input_filename = argv[5];
		char *output_proof_filename = argv[6];
		r1cs_constraint_system<FieldT> cs;
		std::ifstream ci(circuit_filename, ios::binary | ios::in);
		ci >> cs;
		ci.close();
		libsnark::prove<libsnark::default_r1cs_gg_ppzksnark_pp>(cs, proof_key_filename, primary_input_filename, aux_input_filename, output_proof_filename);
		break;
	}
	default:
		cerr << "Unimplemented" << endl;
		return 1;
	}
	return 0;
}


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
	default:
		cerr << "Unimplemented" << endl;
		exit(1);
	}
	exit(0);

	// Read the circuit, evaluate, and translate constraints
	CircuitReader reader(argv[1 + inputStartIndex], argv[2 + inputStartIndex], pb);
	r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);
	// const r1cs_variable_assignment<FieldT> full_assignment =
			// get_variable_assignment_from_gadgetlib2(*pb);
	r1cs_variable_assignment<FieldT> full_assignment;
	std::ifstream fa("full_assignment", ios::binary | ios::in);
	fa >> full_assignment; 
	cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
	cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();
	// std::cout << cs.primary_input_size << " " << cs.auxiliary_input_size << std::endl;
	// std::ofstream fa("full_assignment", ios::binary | ios::out);
	// fa << full_assignment;
	// fa.close();
	// exit(0);


	// extract primary and auxiliary input
	const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(),
			full_assignment.begin() + cs.num_inputs());
	const r1cs_auxiliary_input<FieldT> auxiliary_input(
			full_assignment.begin() + cs.num_inputs(), full_assignment.end());


	// only print the circuit output values if both flags MONTGOMERY and BINARY outputs are off (see CMakeLists file)
	// In the default case, these flags should be ON for faster performance.

#if !defined(MONTGOMERY_OUTPUT) && !defined(OUTPUT_BINARY)
	cout << endl << "Printing output assignment in readable format:: " << endl;
	std::vector<Wire> outputList = reader.getOutputWireIds();
	int start = reader.getNumInputs();
	int end = reader.getNumInputs() +reader.getNumOutputs();	
	for (int i = start ; i < end; i++) {
		cout << "[output]" << " Value of Wire # " << outputList[i-reader.getNumInputs()] << " :: ";
		cout << primary_input[i];
		cout << endl;
	}
	cout << endl;
#endif

	//assert(cs.is_valid());

	// removed cs.is_valid() check due to a suspected (off by 1) issue in a newly added check in their method.
        // A follow-up will be added.
	if(!cs.is_satisfied(primary_input, auxiliary_input)){
		cout << "The constraint system is  not satisifed by the value assignment - Terminating." << endl;
		return -1;
	}


	r1cs_example<FieldT> example(cs, primary_input, auxiliary_input);
	
	const bool test_serialization = false;
	bool successBit = false;
	if(argc == 3) {
		successBit = libsnark::run_r1cs_ppzksnark<libff::default_ec_pp>(example, test_serialization);

	} else {
		// The following code makes use of the observation that 
		// libsnark::default_r1cs_gg_ppzksnark_pp is the same as libff::default_ec_pp (see r1cs_gg_ppzksnark_pp.hpp)
		// otherwise, the following code won't work properly, as GadgetLib2 is hardcoded to use libff::default_ec_pp.
		successBit = libsnark::run_r1cs_gg_ppzksnark<libsnark::default_r1cs_gg_ppzksnark_pp>(
			example, test_serialization);
	}

	if(!successBit){
		cout << "Problem occurred while running the ppzksnark algorithms .. " << endl;
		return -1;
	}	
	return 0;
}


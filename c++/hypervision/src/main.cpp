#include "common.hpp"
#include "hypervision.hpp"

using namespace std;

int main(int argc, char * argv[]) {
	std::string conf_path;
	// Control or data plane (cp/dp).
	std::string stream_type;

	conf_path	= std::string(argv[1]);
	stream_type	= std::string(argv[2]);

	std::cout << conf_path << std::endl;
	std::cout << stream_type << std::endl;

	nlohmann::json conf_j;
	try {
		ifstream fin(conf_path);
		fin >> conf_j;
	} catch (const exception & e) {
		FATAL_ERROR(e.what());
	}

	auto hv1 = make_shared<hypervision::Hypervision>();

	hv1->config_via_json(conf_j);

	if (stream_type == "dp") {
		hv1->stream_dp();
	} else if (stream_type == "cp") {
		hv1->stream_cp();
	} else FATAL_ERROR("Wrong stream type. Available: control plane /data plane (cp/dp).");

	return 0;
}

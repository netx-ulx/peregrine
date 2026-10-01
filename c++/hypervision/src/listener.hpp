#pragma once

#include <string>
#include <memory>

#include "sample.h"

using namespace std;

namespace hypervision {

class Listener final  {
private:
	int sock_recv;
	uint8_t* buffer;
	shared_ptr<sample_t> p_sample;

public:
	Listener(const string& iface);
	~Listener();

	sample_t receive_sample();

	auto inline get_sample() const -> const decltype(p_sample) {
		if (p_sample) {
			return p_sample;
		} else {
			return nullptr;
		}
	}
};

}

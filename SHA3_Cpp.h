//Edit by zq
//All right reserved
//zq0003@163.com
//Version 1.2t
//20161123
#ifndef SHA3_CPP_H__ZQ0913__INCLUDED_
	#define SHA3_CPP_H__ZQ0913__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

namespace ZQs_tools{

#define D_B 1600 
#define D_W 64
#define D_L 6
#define D_C 1024
#define D_NR 24
#define D_D 512

static const int g_rhoTable[5][5] = { { 0,36,3,105,210 },{ 1,300,10,45,66 },{ 190,6,171,15,253 },{ 28,55,153,21,120 },{ 91,276,231,136,78 } };
static const int g_piTable[5][5][2] = { { { 0,0 },{ 3,0 },{ 1,0 },{ 4,0 },{ 2,0 } },{ { 1,1 },{ 4,1 },{ 2,1 },{ 0,1 },{ 3,1 } },{ { 2,2 },{ 0,2 },{ 3,2 },{ 1,2 },{ 4,2 } },{ { 3,3 },{ 1,3 },{ 4,3 },{ 2,3 },{ 0,3 } },{ { 4,4 },{ 2,4 },{ 0,4 },{ 3,4 },{ 1,4 } } };
static const int g_chiTable[5][2] = { { 1,2 },{ 2,3 },{ 3,4 },{ 4,0 },{ 0,1 } };
static const unsigned char g_rcTable[256] = {
	1,0,0,0,0,0,0,0,1,0,1,1,0,0,0,1,1,1,1,0,1,0,0,0,0,1,1,1,1,1,1,1,
	1,0,0,1,0,0,0,0,1,0,1,0,0,1,1,1,1,1,0,1,0,1,0,1,0,1,1,1,0,0,0,0,
	0,1,1,0,0,0,1,0,1,0,1,1,0,0,1,1,0,0,1,0,1,1,1,1,1,1,0,1,1,1,1,0,
	0,1,1,0,1,1,1,0,1,1,1,0,0,1,0,1,0,1,0,0,1,0,1,0,0,0,1,0,0,1,0,1,
	1,0,1,0,0,0,1,1,0,0,1,1,1,0,0,1,1,1,1,0,0,0,1,1,0,1,1,0,0,0,0,1,
	0,0,0,1,0,1,1,1,0,1,0,1,1,1,1,0,1,1,0,1,1,1,1,1,0,0,0,0,1,1,0,1,
	0,0,1,1,0,1,0,1,1,0,1,1,0,1,0,1,0,0,0,0,0,1,0,0,1,1,1,0,1,1,0,0,
	1,0,0,1,0,0,1,1,0,0,0,0,0,0,1,1,1,0,1,0,0,1,0,0,0,1,1,1,0,0,0,1 };
static const unsigned char g_lTaleb[7] = { 0,1,3,7,15,31,63 };

class CSHA3 {
public:
	CSHA3();
	~CSHA3();
	unsigned char FileSPONGE(char *pInFilePath, unsigned char *pZ);
private:
	unsigned char ***A;
	unsigned char **C;
	unsigned char **D;
	unsigned char **At2D;
	unsigned char *At1D;
	unsigned char *RC;
	inline void ArrayPartReverse(unsigned char *A, int b, int e);
	inline void ArrayRightShift(unsigned char *A, int n, int k);
	inline void StringToState(const unsigned char *const S, unsigned char ***A);
	inline void StateToString(unsigned char ***A, unsigned char *S);
	inline void thet(unsigned char ***A);
	inline void rho(unsigned char ***A);
	inline void pi(unsigned char ***A);
	inline void chi(unsigned char ***A);
	inline void l(unsigned char ***A, int ir);
	void KECCAK_P(unsigned char *S);
	void BloSPONGE(unsigned char *pP, int PbitLen, int r, unsigned char *pS);
};
}
#endif//!defined(SHA3_CPP_H__ZQ0913__INCLUDED_)
//Edit by zq
//zq0003@163.com
//Version 1.2t
//20161123
#include "stdafx.h"
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include "SHA3_Cpp.h"
#include "MemAllot_Cpp.h"
using namespace std;
namespace ZQs_tools{
CSHA3::CSHA3()
{
	MemAllot_New_3D(A,5,5,D_W,unsigned char)
	MemAllot_Zero_3D(A,5,5,D_W)
	MemAllot_New_2D(C,5,D_W,unsigned char)
	MemAllot_New_2D(D,5,D_W,unsigned char)
	MemAllot_New_2D(At2D, 5, 5, unsigned char)
	MemAllot_New_1D(At1D, 5, unsigned char)
	MemAllot_New_1D(RC, D_W, unsigned char)
}
CSHA3::~CSHA3() 
{
	MemAllot_Del_3D(A,5,5)
	MemAllot_Del_2D(C,5)
	MemAllot_Del_2D(D,5)
	MemAllot_Del_2D(At2D,5)
	MemAllot_Del_1D(At1D)
	MemAllot_Del_1D(RC)
}
inline void CSHA3::ArrayPartReverse(unsigned char *A,int b,int e)
{
	for(;b<e;b++,e--){
		A[b]^=A[e];
		A[e]^=A[b];
		A[b]^=A[e];
	}
}
inline void CSHA3::ArrayRightShift(unsigned char *A, int n, int k)
{
	k=k%n;
	ArrayPartReverse(A,0,n-k-1);
	ArrayPartReverse(A,n-k,n-1);
	ArrayPartReverse(A,0,n-1);
}
inline void CSHA3::StringToState(const unsigned char *const S, unsigned char ***A)
{
	int i,j,k;
	for(i=0;i<5;i++){
		for(j=0;j<5;j++){
			for(k=0;k<D_W;k++){
				A[i][j][k]=(S[(D_W*(5*j+i)+k)/8]>>((D_W*(5*j+i)+k)%8))&0x01;
			}
		}
	}
}
inline void CSHA3::StateToString(unsigned char ***A, unsigned char *S)
{
	int i,j,k;
	for(i=0;i<25*D_W/8;i++){
		S[i]=0;
	}
	for(i=0;i<5;i++){
		for(j=0;j<5;j++){
			for(k=0;k<D_W;k++){
				S[(D_W*(5*j+i)+k)/8]^=(A[i][j][k]&0x01)<<((D_W*(5*j+i)+k)%8);
			}
		}
	}
}
inline void CSHA3::thet(unsigned char ***A)
{
	int i,j,k;
      
	for(i=0;i<5;i++){
		for(k=0;k<D_W;k++){
			C[i][k]=A[i][0][k]^A[i][1][k]^A[i][2][k]^A[i][3][k]^A[i][4][k];
		}
	}
	for(i=0;i<5;i++){
		for(k=0;k<D_W;k++){
			D[i][k]=C[(i+4)%5][k]^C[(i+1)%5][(D_W+k-1)%D_W];
		}
	}
	for(i=0;i<5;i++){
		for(j=0;j<5;j++){
			for(k=0;k<D_W;k++){
				A[i][j][k]^=D[i][k];
			}
		}
	}
}
inline void CSHA3::rho(unsigned char ***A)
{
	int i,j;
	for(i=0;i<5;i++){
		for(j=0;j<5;j++){
			ArrayRightShift(A[i][j],D_W,g_rhoTable[i][j]%D_W);		
		}
	}
}
inline void CSHA3::pi(unsigned char ***A)
{
	int i,j,k;
	for(k=0;k<D_W;k++){
		for(i=0;i<5;i++){
			for(j=0;j<5;j++){
				At2D[i][j]=A[i][j][k];
			}
		}
		for(i=0;i<5;i++){
			for(j=0;j<5;j++){
				A[i][j][k]=At2D[g_piTable[i][j][0]][g_piTable[i][j][1]];			
			}
		}
	}
}
inline void CSHA3::chi(unsigned char ***A)
{
	int i,j,k;
	for(j=0;j<5;j++){
		for(k=0;k<D_W;k++){
			for(i=0;i<5;i++){
				At1D[i]=A[i][j][k]^((A[g_chiTable[i][0]][j][k]^0x01)&A[g_chiTable[i][1]][j][k]);
			}
			for(i=0;i<5;i++){
				A[i][j][k]=At1D[i];
			}
		}
	}
}
inline void CSHA3::l(unsigned char ***A, int ir)
{
	int k;
	for(k=0;k<D_W;k++){
		RC[k]=0;
	}	
	for(k=0;k<=D_L;k++){
		RC[g_lTaleb[k]]=g_rcTable[k+7*ir];
	}
	for(k=0;k<D_W;k++){
		A[0][0][k]^=RC[k];
	}
}
inline void CSHA3::KECCAK_P(unsigned char *S)
{
	int i;
	StringToState(S,A);
	for(i=2*D_L+12-D_NR;i<2*D_L+12;i++){
		thet(A);
		rho(A);
		pi(A);
		chi(A);
		l(A,i);
	}
	StateToString(A,S);
}
void CSHA3::BloSPONGE(unsigned char *pP, int PbitLen, int r, unsigned char *pS)
{
	if(PbitLen<=0) return;
	int i,j;
	for(i=0;i<PbitLen/r;i++){
		for(j=0;j<r;j++){
			pS[j/8]^=pP[(i*r+j)/8]&(0x01<<(j%8));
		}
		KECCAK_P(pS);		
	}

}
unsigned char CSHA3::FileSPONGE(char *pInFilePath, unsigned char *pZ)
{
	unsigned char *pBuf,*pS;
	long long InFLen, InFLen2;
	int i,r,PadbitLen,PadByteNum,BloLen,BloNum,TailLen,ind;
	ifstream o_InF;
	r=D_B-D_C;
	o_InF.open(pInFilePath, ios::in | ios::binary);
	
	if (!o_InF.is_open()){
		cout << "Error: Open infile" << pInFilePath << "failed.\n";
		return 0x01;
	}
    o_InF.seekg(0, ios::end);
	InFLen = o_InF.tellg();
	o_InF.seekg(0,ios::beg);

	PadbitLen=r-(InFLen*8)%r;
	PadByteNum=PadbitLen/8;
	InFLen2=InFLen+(long long)PadByteNum;
	BloLen=r*100000/8;
	BloNum=(InFLen2-1)/BloLen;
	TailLen=InFLen2%BloLen;
	if(TailLen==0) TailLen=BloLen;
	MemAllot_New_1D(pBuf, (D_B-D_C)*100000/8*sizeof(unsigned char), unsigned char)//
	MemAllot_New_1D(pS, (D_B / 8)*sizeof(unsigned char), unsigned char)
	for(i=0;i<D_B/8;i++){
		pS[i]=0;
	}
	for(i=0;i<BloNum;i++){
		o_InF.read((char *)pBuf,sizeof(unsigned char)*BloLen);
		BloSPONGE(pBuf,BloLen*8,r,pS);
	}
	o_InF.read((char *)pBuf,sizeof(unsigned char)*(TailLen-PadByteNum));
	if(PadbitLen==8) {
		pBuf[TailLen-PadByteNum]=0x86;
		BloSPONGE(pBuf,TailLen*8,r,pS);
	}
	else {
		pBuf[TailLen-PadByteNum]=0x06;
		for(i=TailLen-PadByteNum+1;i<TailLen-1;i++){
			pBuf[i]=0x00;
		}
		pBuf[TailLen-1]=0x80;
		BloSPONGE(pBuf,TailLen*8,r,pS);	
	}
	for(i=0;i<D_D/8;i++){
		pZ[i]=0;
	}	
	ind=0;
	do{
		for(i=0;i<r/8;i++){
			pZ[ind]=pS[i];
			ind++;
		}
		KECCAK_P(pS);
	}while(ind<D_D/8);
	MemAllot_Del_1D(pBuf)
	MemAllot_Del_1D(pS)
	o_InF.close();
	return 0x00;
}
}

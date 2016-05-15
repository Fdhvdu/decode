#include<algorithm>
#include<ios>
#include<iostream>
#include<string>
#include<string_view>
#include<vector>
#include"cryptopp/sha3.h"
using namespace std;

int main(int argc,char **argv)
{
	ios_base::sync_with_stdio(false);
	if(argc!=4)
	{
		cout<<"arguments: [message] [password length] [iteration]"<<endl;
		return 1;
	}
	const unsigned long passwd_len(stoul(argv[2]));
	if(passwd_len<4)
	{
		cout<<"password length should be greater than 3"<<endl;
		return 1;
	}
	if(CryptoPP::SHA3_512::DIGESTSIZE<passwd_len)
	{
		cout<<"password length should be smaller than or equal to "<<CryptoPP::SHA3_512::DIGESTSIZE<<endl;
		return 1;
	}
	unsigned long iteration(stoul(argv[3]));
	if(iteration==0)
	{
		cout<<"iteration cannot be 0"<<endl;
		return 1;
	}
	const string_view legal[]={"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~","0123456789","ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"};
	const auto msg_len(strlen(argv[1]));
	if(any_of(argv[1],argv[1]+msg_len,[&](const auto val) noexcept{return (legal[0].find(val)==string::npos)&&(legal[1].find(val)==string::npos)&&(legal[2].find(val)==string::npos)&&(legal[3].find(val)==string::npos);}))
	{
		cout<<"one of character in the message is not legal"<<endl;
		return 1;
	}
	vector<unsigned char> msg(argv[1],argv[1]+msg_len);
	unsigned char digest[CryptoPP::SHA3_512::DIGESTSIZE];
	do
	{
		CryptoPP::SHA3_512 sha3_512;
		sha3_512.Update(msg.data(),msg.size());
		sha3_512.Final(digest);
		msg.resize(passwd_len);
		for(int i(0);i!=4;++i)
			msg[i]=legal[i][digest[i]%legal[i].size()];
		for(unsigned long i(4);i!=passwd_len;++i)
			msg[i]=legal[digest[i]%4][digest[i]%legal[digest[i]%4].size()];
	}while(--iteration);
	for(unsigned long i(0);i!=passwd_len;++i)
		cout<<msg[i];
	cout<<endl;
}

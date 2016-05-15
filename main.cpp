#include<algorithm>
#include<cstring>
#include<iostream>
#include<iterator>
#include<string>
#include<vector>
#include"cryptopp/sha3.h"
using namespace std;

int main(int argc,char **argv)
{
	const string legal("!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~");
	const string non_alnum("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~");
	ios_base::sync_with_stdio(false);
	if(argc!=3)
	{
		cout<<"arguments: [message] [password length]"<<endl;
		return 0;
	}
	const auto msg_len(strlen(argv[1]));
	if(any_of(argv[1],argv[1]+msg_len,[](const auto val) noexcept{return isgraph(val)==0;}))
	{
		cout<<"one of character is not isgraph"<<endl;
		return 0;
	}
	const auto passwd_len(stoi(argv[2]));
	if(passwd_len<4)
	{
		cout<<"password length should be greater than 3"<<endl;
		return 0;
	}
	vector<unsigned char> msg(argv[1],argv[1]+msg_len);
	unsigned char digest[CryptoPP::SHA3_512::DIGESTSIZE];
	CryptoPP::SHA3_512 sha3_512;
	sha3_512.Update(msg.data(),msg.size());
	sha3_512.Final(digest);
	cout<<non_alnum[digest[0]%(non_alnum.size()-1)]	//minus 1 due to two backslashes
		<<static_cast<char>('0'+(digest[1]%10))
		<<static_cast<char>('A'+(digest[2]%26))
		<<static_cast<char>('a'+(digest[3]%26));
	for(size_t i(4);i!=passwd_len;++i)
		cout<<legal[digest[i]%(legal.size()-1)];	//minus 1 due to two backslashes
	cout<<endl;
}

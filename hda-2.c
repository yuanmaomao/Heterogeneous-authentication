#include <pbc.h>
#include <pbc_time.h>
int main(void)
{
	double time1, time2;
    pairing_t pairing;
    element_t s, x, r, h, hr, temp1, temp3, temp4;
	element_t P, PUB, Sk, Pk, Ss, u, v, temp2, temp6; 
	element_t g, w, wr, temp5, temp7;
	a_param_input(pairing);//自动输入类型A的配对参数
//将变量初始化为G1中的元素
	element_init_G1(P, pairing);
    element_init_G1(PUB, pairing);
    element_init_G1(Sk, pairing);
    element_init_G1(Pk, pairing);
    element_init_G1(Ss, pairing);
	element_init_G1(u, pairing);
	element_init_G1(v, pairing);
	element_init_G1(temp2, pairing);
	element_init_G1(temp6, pairing);
//将变量初始化为Zr中的元素
	element_init_Zr(s, pairing);
	element_init_Zr(x, pairing);
	element_init_Zr(r, pairing);
	element_init_Zr(h, pairing);
	element_init_Zr(hr, pairing);
	element_init_Zr(temp1, pairing);
	element_init_Zr(temp3, pairing);
	element_init_Zr(temp4, pairing);
//将变量初始化为GT中的元素
    element_init_GT(g, pairing);
    element_init_GT(w, pairing);
	element_init_GT(wr, pairing);
    element_init_GT(temp5, pairing);
	element_init_GT(temp7, pairing);
	if (!pairing_is_symmetric(pairing)) 
	{
		fprintf(stderr, "only works with symmetric pairing\n");
		exit(1);
    }

	/////////////////////////////////////////////////////////
    printf("HDA-2 scheme\n");
	printf("Setup\n");//系统建立阶段
	time1 = get_time();
    element_random(s);//主密钥s
    element_random(P);//G1的生成元
    element_mul_zn(PUB, P, s);//pub=sP
	pairing_apply(g, P, P, pairing);//公共参数g
	element_printf("s = %B\n", s);
	element_printf("P = %B\n", P);
	element_printf("P_{PUB} = %B\n", PUB);
	element_printf("g = %B\n", g);
	time2 = get_time();
	printf("the time of setup phase = %fs\n", time2 - time1);//求Setup阶段的时间

	printf("Extract\n");//密钥提取阶段
	time1 = get_time();
    element_random(x);//PKI系统上传的公共随机数x
	element_invert(temp3,x);//x倒数
    element_mul_zn(Sk, P, temp3);//PKI发送方私钥
	element_printf("SK_A = %B\n", Sk);
    element_mul_zn(Pk, P, x);//PKI发送方公钥
	element_printf("PK_A = %B\n", Pk);
	element_from_hash(temp1, "H1IDR" ,5);//H1(ID)
	element_add(temp3, temp1, s);//+和
    element_invert(temp4 , temp3);//取倒数运算
    element_mul_zn(Ss, P ,temp4);//分配接收方私钥SID=(1/(H1(ID)+S))P
	element_printf("S_{ID} = %B\n", Ss);
	time2 = get_time();
	printf("the time of extract phase = %fs\n", time2 - time1);
   
	printf("Authenticate & Encrypt\n");//否认认证加密阶段
	time1 = get_time();
	element_random(r);//步骤1
	element_printf("x= %B\n", r);
	element_mul_zn(u,Pk,r);//步骤2
	element_printf("u = %B\n", u);
	element_from_hash(h, "H1mUT", 5);//步骤3
	element_printf("h = %B\n", h);
	element_add(temp3, r, h);
	element_mul_zn(v, Ss, temp3);//步骤4
	element_printf("v = %B\n", v);
	element_mul_zn(temp2,P,temp1);//!!!!!!!!!!!!!!
    element_add(temp6,temp2,PUB);
	pairing_apply(w, v, temp6,pairing);//步骤5
	element_printf("w = %B\n", w);
	time2 = get_time();
	printf("the time of Authenticate & Encrytp phase = %fs\n", time2 - time1);

	
	printf("Deniable-Decrypt\n");
	time1 = get_time();
	element_from_hash(hr, "H1mUT", 5);//计算hr
	element_printf("hr = %B\n", hr);
	pairing_apply(temp7, u, Sk, pairing);
	element_printf("temp7 = %B\n", temp7);
    element_pow_zn(temp5,g,h);
	element_printf("temp5 = %B\n", temp5);
	element_mul(wr, temp5 ,temp7);
	element_printf("wr = %B\n", wr);
	if(element_cmp(h, hr))//比较如果哈希值变化则一定有改动不接收数据
	{
		printf("the authenticator of message is valid1111\n");
	}
    else if(element_cmp(wr, w))//双线性验证签名
	{
		printf("the authenticator of message is valid2222\n");
	}
	else
	{
		printf("the authenticator of message is confirmd\n");
	}
	time2 = get_time();
	printf("the time of Deniable-Decrytp phase = %fs\n", time2 - time1);
    element_clear(r);  
	getchar();
    return 0; 
}



#include <pbc.h>
#include <pbc_time.h>
int main(void)
{
	double time1, time2;
    pairing_t pairing;
    element_t s, x, r, h, hr, temp1, temp3, temp4;
	element_t P, PUB, Sk, Pk, Ss, u, v, temp2, temp6; 
	element_t g, w, wr, temp5, temp7;
	a_param_input(pairing);//�Զ���������A����Բ���
//��������ʼ��ΪG1�е�Ԫ��
	element_init_G1(P, pairing);
    element_init_G1(PUB, pairing);
    element_init_G1(Sk, pairing);
    element_init_G1(Pk, pairing);
    element_init_G1(Ss, pairing);
	element_init_G1(u, pairing);
	element_init_G1(v, pairing);
	element_init_G1(temp2, pairing);
	element_init_G1(temp6, pairing);
//��������ʼ��ΪZr�е�Ԫ��
	element_init_Zr(s, pairing);
	element_init_Zr(x, pairing);
	element_init_Zr(r, pairing);
	element_init_Zr(h, pairing);
	element_init_Zr(hr, pairing);
	element_init_Zr(temp1, pairing);
	element_init_Zr(temp3, pairing);
	element_init_Zr(temp4, pairing);
//��������ʼ��ΪGT�е�Ԫ��
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
	printf("Setup\n");//ϵͳ�����׶�
	time1 = get_time();
    element_random(s);//����Կs
    element_random(P);//G1������Ԫ
    element_mul_zn(PUB, P, s);//pub=sP
	pairing_apply(g, P, P, pairing);//��������g
	element_printf("s = %B\n", s);
	element_printf("P = %B\n", P);
	element_printf("P_{PUB} = %B\n", PUB);
	element_printf("g = %B\n", g);
	time2 = get_time();
	printf("the time of setup phase = %fs\n", time2 - time1);//��Setup�׶ε�ʱ��

	printf("Extract\n");//��Կ��ȡ�׶�
	time1 = get_time();
    element_random(x);//PKIϵͳ�ϴ��Ĺ��������x
	element_invert(temp3,x);//x����
    element_mul_zn(Sk, P, temp3);//PKI���ͷ�˽Կ
	element_printf("SK_A = %B\n", Sk);
    element_mul_zn(Pk, P, x);//PKI���ͷ���Կ
	element_printf("PK_A = %B\n", Pk);
	element_from_hash(temp1, "H1IDR" ,5);//H1(ID)
	element_add(temp3, temp1, s);//+��
    element_invert(temp4 , temp3);//ȡ��������
    element_mul_zn(Ss, P ,temp4);//������շ�˽ԿSID=(1/(H1(ID)+S))P
	element_printf("S_{ID} = %B\n", Ss);
	time2 = get_time();
	printf("the time of extract phase = %fs\n", time2 - time1);
   
	printf("Authenticate & Encrypt\n");//������֤���ܽ׶�
	time1 = get_time();
	element_random(r);//����1
	element_printf("x= %B\n", r);
	element_mul_zn(u,Pk,r);//����2
	element_printf("u = %B\n", u);
	element_from_hash(h, "H1mUT", 5);//����3
	element_printf("h = %B\n", h);
	element_add(temp3, r, h);
	element_mul_zn(v, Ss, temp3);//����4
	element_printf("v = %B\n", v);
	element_mul_zn(temp2,P,temp1);//!!!!!!!!!!!!!!
    element_add(temp6,temp2,PUB);
	pairing_apply(w, v, temp6,pairing);//����5
	element_printf("w = %B\n", w);
	time2 = get_time();
	printf("the time of Authenticate & Encrytp phase = %fs\n", time2 - time1);

	
	printf("Deniable-Decrypt\n");
	time1 = get_time();
	element_from_hash(hr, "H1mUT", 5);//����hr
	element_printf("hr = %B\n", hr);
	pairing_apply(temp7, u, Sk, pairing);
	element_printf("temp7 = %B\n", temp7);
    element_pow_zn(temp5,g,h);
	element_printf("temp5 = %B\n", temp5);
	element_mul(wr, temp5 ,temp7);
	element_printf("wr = %B\n", wr);
	if(element_cmp(h, hr))//�Ƚ������ϣֵ�仯��һ���иĶ�����������
	{
		printf("the authenticator of message is valid1111\n");
	}
    else if(element_cmp(wr, w))//˫������֤ǩ��
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



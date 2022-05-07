package com.dizsun.timechain.sm;

import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;

public class SM2Utils 
{
	public static byte[] encrypt(byte[] publicKey, byte[] data)
	{
		if (publicKey == null || publicKey.length == 0)
		{
			return null;
		}
		
		if (data == null || data.length == 0)
		{
			return null;
		}
		
		byte[] source = new byte[data.length];
		System.arraycopy(data, 0, source, 0, data.length);

        byte[] formatedPubKey;
        if (publicKey.length == 64){
            //添加一字节标识，用于ECPoint解析
            formatedPubKey = new byte[65];
            formatedPubKey[0] = 0x04;
            System.arraycopy(publicKey,0,formatedPubKey,1,publicKey.length);
        }
        else {
			formatedPubKey = publicKey;
		}
		
		com.dizsun.timechain.sm.Cipher cipher = new com.dizsun.timechain.sm.Cipher();
		SM2 sm2 = SM2.Instance();
		ECPoint userKey = sm2.ecc_curve.decodePoint(formatedPubKey);
		
		ECPoint c1 = cipher.Init_enc(sm2, userKey);
		cipher.Encrypt(source);
		byte[] c3 = new byte[32];
		cipher.Dofinal(c3);
		
		DERInteger x = new DERInteger(c1.getX().toBigInteger());
		DERInteger y = new DERInteger(c1.getY().toBigInteger());
		DEROctetString derDig = new DEROctetString(c3);
		DEROctetString derEnc = new DEROctetString(source);
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(x);
		v.add(y);
		v.add(derDig);
		v.add(derEnc);
		DERSequence seq = new DERSequence(v);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		DEROutputStream dos = new DEROutputStream(bos);
        try {
            dos.writeObject(seq);
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
	
	public static byte[] decrypt(byte[] privateKey, byte[] encryptedData)
	{
		if (privateKey == null || privateKey.length == 0)
		{
			return null;
		}
		
		if (encryptedData == null || encryptedData.length == 0)
		{
			return null;
		}
		
		byte[] enc = new byte[encryptedData.length];
		System.arraycopy(encryptedData, 0, enc, 0, encryptedData.length);
		
		SM2 sm2 = SM2.Instance();
		BigInteger userD = new BigInteger(1, privateKey);
		
		ByteArrayInputStream bis = new ByteArrayInputStream(enc);
		ASN1InputStream dis = new ASN1InputStream(bis);
        try {
            DERObject derObj = dis.readObject();
            ASN1Sequence asn1 = (ASN1Sequence) derObj;
            DERInteger x = (DERInteger) asn1.getObjectAt(0);
            DERInteger y = (DERInteger) asn1.getObjectAt(1);
            ECPoint c1 = sm2.ecc_curve.createPoint(x.getValue(), y.getValue(), true);

            com.dizsun.timechain.sm.Cipher cipher = new com.dizsun.timechain.sm.Cipher();
            cipher.Init_dec(userD, c1);
            DEROctetString data = (DEROctetString) asn1.getObjectAt(3);
            enc = data.getOctets();
            cipher.Decrypt(enc);
            byte[] c3 = new byte[32];
            cipher.Dofinal(c3);
            return enc;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 使用默认ID计算
     * @param privateKey
     * @param sourceData
     * @return
     */
	//签名
    public static byte[] sign(byte[] privateKey, byte[] sourceData){
        String userId = "1234567812345678";

        return sign(userId.getBytes(), privateKey, sourceData);
    }
	public static byte[] sign(byte[] userId, byte[] privateKey, byte[] sourceData)
	{
		if (privateKey == null || privateKey.length == 0)
		{
			return null;
		}
		
		if (sourceData == null || sourceData.length == 0)
		{
			return null;
		}
		
		SM2 sm2 = SM2.Instance();
		BigInteger userD = new BigInteger(1,privateKey);

		
		ECPoint userKey = sm2.ecc_point_g.multiply(userD);

		
		com.dizsun.timechain.sm.SM3Digest sm3 = new com.dizsun.timechain.sm.SM3Digest();
		byte[] z = sm2.sm2GetZ(userId, userKey);

		
		sm3.update(z, 0, z.length);
	    sm3.update(sourceData, 0, sourceData.length);
	    byte[] md = new byte[32];
	    sm3.doFinal(md, 0);
	    

	    
	    com.dizsun.timechain.sm.SM2Result sm2Result = new com.dizsun.timechain.sm.SM2Result();
	    sm2.sm2Sign(md, userD, userKey, sm2Result);

	    
	    DERInteger d_r = new DERInteger(sm2Result.r);
	    DERInteger d_s = new DERInteger(sm2Result.s);
	    ASN1EncodableVector v2 = new ASN1EncodableVector();
	    v2.add(d_r);
	    v2.add(d_s);
	    DERObject sign = new DERSequence(v2);
        return sign.getDEREncoded();
	}

    /**
     * 使用默认id计算
     * @param publicKey
     * @param sourceData
     * @param signData
     * @return
     */
	//验证签名
    public static boolean verifySign(byte[] publicKey, byte[] sourceData, byte[] signData){
        String userId = "1234567812345678";
        return verifySign(userId.getBytes(),publicKey,sourceData,signData);
    }
	@SuppressWarnings("unchecked")
	public static boolean verifySign(byte[] userId, byte[] publicKey, byte[] sourceData, byte[] signData)
	{
		if (publicKey == null || publicKey.length == 0)
		{
			return false;
		}
		
		if (sourceData == null || sourceData.length == 0)
		{
			return false;
		}

        byte[] formatedPubKey;
        if (publicKey.length == 64){
            //添加一字节标识，用于ECPoint解析
            formatedPubKey = new byte[65];
            formatedPubKey[0] = 0x04;
            System.arraycopy(publicKey,0,formatedPubKey,1,publicKey.length);
        }
        else {
			formatedPubKey = publicKey;
		}
		
		SM2 sm2 = SM2.Instance();
		ECPoint userKey = sm2.ecc_curve.decodePoint(formatedPubKey);

		com.dizsun.timechain.sm.SM3Digest sm3 = new com.dizsun.timechain.sm.SM3Digest();
		byte[] z = sm2.sm2GetZ(userId, userKey);
		sm3.update(z, 0, z.length);
		sm3.update(sourceData, 0, sourceData.length);
	    byte[] md = new byte[32];
	    sm3.doFinal(md, 0);

		
	    ByteArrayInputStream bis = new ByteArrayInputStream(signData);
	    ASN1InputStream dis = new ASN1InputStream(bis);
		com.dizsun.timechain.sm.SM2Result sm2Result = null;
		try {
			DERObject derObj = dis.readObject();
			Enumeration<DERInteger> e = ((ASN1Sequence) derObj).getObjects();
			BigInteger r = ((DERInteger)e.nextElement()).getValue();
			BigInteger s = ((DERInteger)e.nextElement()).getValue();
			sm2Result = new com.dizsun.timechain.sm.SM2Result();
			sm2Result.r = r;
			sm2Result.s = s;

			sm2.sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
			return sm2Result.r.equals(sm2Result.R);
		} catch (IOException e1) {
			e1.printStackTrace();
            return false;
        }
	}

//生成密钥对
    public static com.dizsun.timechain.sm.Sm2KeyPair generateKeyPair(){
        SM2 sm2 = SM2.Instance();
        AsymmetricCipherKeyPair keypair = sm2.ecc_key_pair_generator.generateKeyPair();
        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) keypair.getPrivate();
        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) keypair.getPublic();


        byte[] priKey = new byte[32];
        byte[] pubKey = new byte[64];

        byte[] bigNumArray = ecpriv.getD().toByteArray();
        System.arraycopy(bigNumArray, bigNumArray[0]==0?1:0, priKey, 0, 32);
        System.arraycopy(ecpub.getQ().getEncoded(), 1, pubKey, 0, 64);



        return new com.dizsun.timechain.sm.Sm2KeyPair(priKey, pubKey);
    }

}

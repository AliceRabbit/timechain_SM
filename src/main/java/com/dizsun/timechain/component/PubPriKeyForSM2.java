package com.dizsun.timechain.component;

import com.dizsun.timechain.sm.SM2Utils;
import com.dizsun.timechain.sm.Sm2KeyPair;
import com.dizsun.timechain.sm.Util;
import org.apache.log4j.Logger;


import java.nio.charset.StandardCharsets;
import java.security.*;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

public class PubPriKeyForSM2 {

	private byte[] publicKey;
	private String publicKeyBase64;
	private byte[] privateKey;
	private Logger logger = Logger.getLogger(PublicKey.class);

	public PubPriKeyForSM2() {
	}

	public void init() {
		try {
			Sm2KeyPair keyPair = SM2Utils.generateKeyPair();


			/** 得到公钥、私钥 */
			publicKey = keyPair.getPubKey();
			privateKey = keyPair.getPriKey();


			publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public byte[] getPriKey() {
		return privateKey;
	}

	public void setPriKey(byte[] priKey) {
		this.privateKey = priKey;
	}

	public byte[] getPubKey() {
		return publicKey;
	}

	public void setPubKey(byte[] pubKey) {
		this.publicKey = pubKey;
	}

	public void setPublicKeyBase64(String publicKeyBase64) {
		this.publicKeyBase64 = publicKeyBase64;
	}

	public String getPublicKeyBase64() {
		return publicKeyBase64;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		PubPriKeyForSM2 pubPriKey = (PubPriKeyForSM2) o;
		return publicKey.equals(pubPriKey.publicKey) && privateKey.equals(pubPriKey.privateKey);
	}

	@Override
	public int hashCode() {
		return Objects.hash(publicKey, privateKey);
	}

	@Override
	public String toString() {
		return "PubPriKey{" + "publicKey='" + publicKey + '\'' + ", privateKey='" + privateKey + '\'' + '}';
	}

	/**
	 * 加密方法
	 *
	 * @param source 源数据
	 * @return
	 * @throws Exception
	 */
	public String encrypt(String source) {
		try {
			byte[] data = source.getBytes();

			/* 执行加密操作 */
			byte[] encryptedData = SM2Utils.encrypt(publicKey, data);

			return Base64.getEncoder().encodeToString(encryptedData);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 解密算法
	 *
	 * @param cryptograph 密文
	 * @return
	 * @throws Exception
	 */
	public String decrypt(String cryptograph) {
		try {

			byte[] encryptedData = Base64.getDecoder().decode(cryptograph);

			/* 执行解密操作 */
			String decryptedData = new String(SM2Utils.decrypt(privateKey, encryptedData));

			return  decryptedData;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

	}

	public String decrypt(String _publicKeyBase64, String cryptograph) {
		try {

			byte[] key = Base64.getDecoder().decode(_publicKeyBase64);
			byte[] encryptedData = Base64.getDecoder().decode(cryptograph);
			/* 执行解密操作 */

			String decryptedData = new String(SM2Utils.decrypt(key, encryptedData));

			return decryptedData;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 签名
	 *
	 * @param source 待签名内容
	 * @return
	 * @throws Exception
	 */
	public String sign(String source){
		try {
			byte[] data = source.getBytes();

			/* 执行签名操作 */
			byte[] signData = SM2Utils.sign(privateKey, data);

			return Base64.getEncoder().encodeToString(signData);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 验签
	 *
	 * @param publicKeyBase64 base64后的验签密钥
	 * @param sourceData 原始内容
	 * @param signDataBase64 签名
	 * @return
	 * @throws Exception
	 */
	public boolean verify(String publicKeyBase64,String sourceData, String signDataBase64){
		try {
			byte[] key = Base64.getDecoder().decode(publicKeyBase64);
			byte[] signData = Base64.getDecoder().decode(signDataBase64);
			/* 执行验证操作 */

			return SM2Utils.verifySign(key, sourceData.getBytes(), signData);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

}

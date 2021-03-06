package com.dizsun.timechain.sm;

/**
 * Created by yuhc on 16-2-21.
 */
public class Sm2KeyPair {
    private byte[] priKey;
    private byte[] pubKey;
    private String publicKeyBase64;
    
    public Sm2KeyPair(byte[] priKey, byte[] pubKey){
        this.priKey = priKey;
        this.pubKey = pubKey;
    }

    public byte[] getPriKey() {
        return priKey;
    }

    public void setPriKey(byte[] priKey) {
        this.priKey = priKey;
    }

    public byte[] getPubKey() {
        return pubKey;
    }

    public void setPubKey(byte[] pubKey) {
        this.pubKey = pubKey;
    }

}

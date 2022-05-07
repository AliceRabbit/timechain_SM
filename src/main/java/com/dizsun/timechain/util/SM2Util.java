package com.dizsun.timechain.util;

import com.dizsun.timechain.component.PubPriKeyForSM2;
import com.dizsun.timechain.service.PersistenceService;

public class SM2Util {

    private PubPriKeyForSM2 pubPriKey;

    private PersistenceService persistenceService = PersistenceService.getInstance();

    private SM2Util() {
    }

    private static class Holder{
        private static final SM2Util sm2Util = new SM2Util();
    }

    public static SM2Util getInstance() {
        return Holder.sm2Util;
    }

    public PubPriKeyForSM2 getPubPriKey() {
        return pubPriKey;
    }

    public void setPubPriKey(PubPriKeyForSM2 pubPriKey) {
        this.pubPriKey = pubPriKey;
    }

    public void init(String localHost) {
        pubPriKey = persistenceService.pubPriKeysUpload(localHost);
        if (pubPriKey == null) {
            pubPriKey = new PubPriKeyForSM2();
            pubPriKey.init();
            persistenceService.pubPriKeysPersistence(localHost, pubPriKey);
        }
    }
}

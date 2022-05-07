package com.dizsun.timechain.constant;

import java.util.ArrayList;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import com.dizsun.timechain.interfaces.ISubscriber;
import com.dizsun.timechain.util.DateUtil;

/**
 * 广播时间变化事件,相当于计时器
 */
public class Broadcaster {
	private ScheduledThreadPoolExecutor scheduled;
	private ArrayList<ISubscriber> subscribers;
	private DateUtil dateUtil;

	public Broadcaster() {
		subscribers = new ArrayList<>();
		dateUtil = DateUtil.getInstance();
		dateUtil.init();
	}

	private static class Holder {
		public static Broadcaster instance = new Broadcaster();
	}

	public static Broadcaster getInstance() {
		return Holder.instance;
	}

	public void broadcast() {
		scheduled = new ScheduledThreadPoolExecutor(2);
		scheduled.scheduleAtFixedRate(new Runnable() {
			@Override
			public void run() {
				// TODO Auto-generated method stub
				if (dateUtil.getCurrentSecond() == 0) {
					for (ISubscriber s : subscribers) {
						s.doPerRunning();
					}
				} else if (dateUtil.getCurrentSecond() == 35) {
					for (ISubscriber s : subscribers) {
						s.doPerTP();
					}
				} else if (dateUtil.getCurrentSecond() == 40) {
					for (ISubscriber s : subscribers) {
						s.doPerTC();
					}
				} else if (dateUtil.getCurrentSecond() == 55) {
					for (ISubscriber s : subscribers) {
						s.doPerTE();
					}
				}
			}
		}, 0, 1000, TimeUnit.MILLISECONDS);
	}

	public void subscribe(ISubscriber subscriber) {
		subscribers.add(subscriber);
	}

	public void unSubscribe(ISubscriber subscriber) {
		subscribers.remove(subscriber);
	}

	public void destroy() {
		if (scheduled != null) {
			scheduled.shutdownNow();
			scheduled = null;
		}
	}

}

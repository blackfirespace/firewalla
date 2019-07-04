'use strict';

const rclient = require('../../util/redis_manager.js').getRedisClient();

let instance = null;
const key = "ratelimit";
const cleanupInterval = 3600 * 1000;
const max = 576;

class RateLimit {
  constructor() {
    if(instance === null) {
      instance = this;

      this.lastExpireDate = null;
      this.lastUsed = null;
      this.lastLimit = null;

      this.cleanup();
      setInterval(() => {
        this.cleanup();
      }, cleanupInterval);
    }

    return instance;
  }

  async cleanup() {
    return rclient.zremrangebyrankAsync(key, 0, -1 * max);
  }

  async recordRate(headers = {}) {
    const expireDate = headers["x-ratelimit-reset"];
    const limit = headers["x-ratelimit-limit"];
    const remaining = headers["x-ratelimit-remaining"];
    if(!expireDate || !limit || !remaining) {
      return;
    }

    const used = limit - remaining;

    // time to eject to redis
    if(this.lastExpireDate && this.lastExpireDate !== expireDate) {
      // this records rate limit for every cycle
      const result = JSON.stringify({used: this.lastUsed, limit: this.lastLimit});
      await rclient.zaddAsync(key, this.lastExpireDate, result);
    }

    this.lastExpireDate = expireDate;
    this.lastUsed = used;
    this.lastLimit = limit;
  }
}

module.exports = new RateLimit();
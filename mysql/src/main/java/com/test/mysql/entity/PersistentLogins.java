package com.test.mysql.entity;

import javax.persistence.*;
import java.util.Date;
/**
 * 记住用户登陆状态的实体建模
 * @author mhs123
 *
 */
@Entity
@Table(name = "persistent_logins")
public class PersistentLogins implements java.io.Serializable{
    @Id
    @Column(name = "series", length = 64, nullable = false)
    private String series;
    @Column(name = "username", length = 64, nullable = false)
    private String username;//用户名
    @Column(name = "token", length = 64, nullable = false)
    private String token;//令牌
    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "last_used", nullable = false)
    private Date last_used;//最后登陆时间

    public PersistentLogins() {
    }

    public String getSeries() {
        return series;
    }

    public void setSeries(String series) {
        this.series = series;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Date getLast_used() {
        return last_used;
    }

    public void setLast_used(Date last_used) {
        this.last_used = last_used;
    }
}

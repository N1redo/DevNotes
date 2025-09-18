# 简介

**Spring Security** 是 Spring 家族中的一个安全管理框架。相比与另外一个安全框架**Shiro**，它提供了更丰富的功能，社区资源也比Shiro丰富。

一般来说中大型的项目都是使用**SpringSecurity** 来做安全框架。小项目有Shiro的比较多，因为相比与SpringSecurity，Shiro的上手更加的简单。

一般Web应用的需要进行**认证**和**授权**。

**认证：验证当前访问系统的是不是本系统的用户，并且要确认具体是哪个用户**

**授权：经过认证后判断当前用户是否有权限进行某个操作**

而认证和授权也是SpringSecurity作为安全框架的核心功能。

# 认证

## 登录校验流程

![](image/登录校验流程.png)

## 原理初探

了解SpringSecurity流程。

### SpringSecurity完整流程

SpringSecurity的原理其实就是一个**过滤器链**，内部包含了提供各种功能的过滤器。（图中只展示核心过滤器）

![](image/过滤器链.png)

**UsernamePasswordAuthenticationFilter**：负责处理在登录页面填写了用户名和密码之后的登录请求，它负责认证的主要工作内容。

**ExceptionTranslationFilter**：处理过滤链中抛出的任何AccessDeniedException（访问异常）和AuthenticationException（认证异常）。

**FilterSecurityInterceptor**：负责权限校验的过滤器。

### 认证流程详解

![](image/认证流程.png)

Authentication（认证）接口：它的实现类，表示当前访问系统的用户，封装了用户相关信息。

AuthenticationManager接口：定义了认证Authentication的方法。

UserDetailsService接口：加载用户特定数据的核心接口。里面定义了一个根据用户名查询用户信息的方法。

UserDetails接口：提供核心用户信息。通过UserDetailsService根据用户名获取处理的用户信息要封装成UserDetails对象返回。然后将这些信息封装到Authentication对象中。

## 认证流程

### 思路分析

登录
- 自定义登录接口
    - 调用ProviderManager的方法进行认证，如果认证通过生成jwt
    - 把用户信息存入redis中
- 自定义UserDetailsService
    - 在这个实现类中去查询数据库

校验
- 定义JWT认证过滤器
    - 获取token
    - 解析token获取其中的userid
    - 从redis中获取用户信息
    - 存入SecurityContextHolder

### 实现

#### 数据库校验用户

自定义一个UserDetailsServiceImpl去实现UserDetailsService，让SpringSecurity使用我们的UserDetailsService。然后在实现类中实现查询数据库中的用户信息。

**代码实现**

创建一个类实现UserDetailsService接口，重写其中的方法。根据用户名从数据库中查询用户信息。

```java
/**  
 * @Description 登录认证  
 * @Author nhh  
 * @Date 2025/9/18 16:28  
 */
@Service  
public class UserDetailsServiceImpl implements UserDetailsService {  
  
    @Autowired  
    private UserMapper userMapper;  
  
    @Override  
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {  
        // 根据用户名查询用户信息  
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();  
        queryWrapper.eq(User::getUserName, username);  
        User user = userMapper.selectOne(queryWrapper);  
        // 异常提醒  
        if (Objects.isNull(user)) {  
            throw new RuntimeException("用户不存在");  
        }  
        return new LoginUser(user);  
    }  
}
```

因为UserDetailsService方法的返回值是UserDetails类型，所以需要定义一个类，实现该接口，把用户信息封装在其中。

```java
/**  
 * @Description 登录用户  
 * @Author nhh  
 * @Date 2025/9/18 16:37  
 */
@Data  
@AllArgsConstructor  
@NoArgsConstructor  
public class LoginUser implements UserDetails {  
  
    private User user;  
  
    @Override  
    public Collection<? extends GrantedAuthority> getAuthorities() {  
        return Collections.emptyList();  
    }  
  
    @Override  
    public String getPassword() {  
        return user.getPassword();  
    }  
  
    @Override  
    public String getUsername() {  
        return user.getUserName();  
    }  
  
    @Override  
    public boolean isAccountNonExpired() {  
        return false;  
    }  
  
    @Override  
    public boolean isAccountNonLocked() {  
        return false;  
    }  
  
    @Override  
    public boolean isCredentialsNonExpired() {  
        return false;  
    }  
  
    @Override  
    public boolean isEnabled() {  
        return false;  
    }  
}
```

#### 密码加密存储

使用SpringSecurity为我们提供的BCryptPasswordEncoder。

只需要使用把BCryptPasswordEncoder对象注入Spring容器中，SpringSecurity就会使用该PasswordEncoder来进行密码校验。

可以定义一个SpringSecurity的配置类，SpringSecurity要求这个配置类要继承WebSecurityConfigurerAapter。

```java
/**  
 * @Description SecurityConfig  
 * @Author nhh  
 * @Date 2025/9/18 17:29  
 */
@Configuration  
public class SecurityConfig extends WebSecurityConfigurerAdapter {  
  
    @Bean  
    public PasswordEncoder passwordEncoder() {  
        return new BCryptPasswordEncoder();  
    }  
  
}
```

#### 登录接口
# 授权
package com.mmall.service.Impl;

import com.mmall.common.Const;
import com.mmall.common.ServerResponse;
import com.mmall.common.TokenCache;
import com.mmall.dao.UserMapper;
import com.mmall.pojo.User;
import com.mmall.service.IUserService;
import com.mmall.util.MD5Util;
import net.sf.jsqlparser.schema.Server;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * Created by Shuhua Song
 *
 */

@Service("iUserService")
public class UserServiceImpl implements IUserService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public ServerResponse<User> login(String username, String password) {
        int resultCount = userMapper.checkUsername(username);
        if(resultCount == 0){
            return ServerResponse.createByErrorMessage("The user is not Exist!!");
        }
        //todo login password MD5
        String md5Password = MD5Util.MD5EncodeUtf8(password);
        User user = userMapper.selectLogin(username, md5Password );
        if(user == null){
            return ServerResponse.createByErrorMessage("Password is Wrong");
        }
        user.setPassword(StringUtils.EMPTY);
        return ServerResponse.createBySuccess("Login Successly", user);
    }

    public ServerResponse<String> register(User user){
        ServerResponse validResponse = this.checkValid(user.getUsername(), Const.USERNAME);
        if(!validResponse.isSuccess()){
            return validResponse;
        }
        validResponse = this.checkValid(user.getEmail(), Const.EMAIL);
        if(!validResponse.isSuccess()){
            return validResponse;
        }
        user.setRole(Const.Role.ROLE_CUSTOMER);

        //MD5 encryption
        user.setPassword(MD5Util.MD5EncodeUtf8(user.getPassword()));
        int resultCount = userMapper.insert(user);
        if(resultCount == 0){
            return ServerResponse.createByErrorMessage("Registration Failed");
        }
        return ServerResponse.createBySuccessMessage("Registration Successfully");
    }

    public ServerResponse<String> checkValid(String str, String type){
         if(StringUtils.isNotBlank(type)){
             // start check
             if(Const.USERNAME.equals(type)){
                 int resultCount = userMapper.checkUsername(str);
                 if(resultCount > 0){
                     return ServerResponse.createByErrorMessage("The user is already exist");
                 }
             }
             if(Const.EMAIL.equals(type)){
                 int resultCount = userMapper.checkEmail(str);
                 if(resultCount > 0){
                     return ServerResponse.createByErrorMessage("The email is already exist");
                 }
             }
         }else{
             return ServerResponse.createByErrorMessage("The parameter is wrong");
         }
         return ServerResponse.createBySuccessMessage("Check Successfully");
    }

    public ServerResponse selectQuestion(String username){
        ServerResponse validResponse = this.checkValid(username, Const.USERNAME);
        if(validResponse.isSuccess()){
            //the user is not exist
            return ServerResponse.createByErrorMessage("The user is not exist");
        }
        String question = userMapper.selectQuestionByUsername(username);
        if(StringUtils.isNotBlank(question)){
            return ServerResponse.createBySuccess(question);
        }
        return ServerResponse.createByErrorMessage("The question for password is null");
    }

    public ServerResponse<String> checkAnswer(String username, String question, String answer){
        int resultCount = userMapper.checkAnswer(username, question, answer);
        if(resultCount > 0){
            // it decrates the question and answer is belong to this user, and it is correct
            String forgetToken = UUID.randomUUID().toString();
            TokenCache.setKey(TokenCache.TOKEN_PREFIX + username, forgetToken);
            return ServerResponse.createBySuccess(forgetToken);
        }
        return ServerResponse.createByErrorMessage("The answer for the question is wrong");
    }

    public ServerResponse<String> forgetRestPassword(String username, String passwordNew, String forgetToken){
        if(StringUtils.isBlank(forgetToken)){
            return ServerResponse.createByErrorMessage("The parameter is wrong, need to transfer token");
        }
        ServerResponse validResponse = this.checkValid(username, Const.USERNAME);
        if(validResponse.isSuccess()){
            //the user is not exist
            return ServerResponse.createByErrorMessage("The user is not exist");
        }
        String token = TokenCache.getKey(TokenCache.TOKEN_PREFIX +username);

        if(StringUtils.isBlank(token)){
            return ServerResponse.createByErrorMessage("token has expired");
        }
        if(StringUtils.equals(forgetToken, token)){
            String md5Password = MD5Util.MD5EncodeUtf8(passwordNew);
            int rowCount = userMapper.updatePasswordByUsername(username, md5Password);
            if(rowCount > 0){
                return ServerResponse.createBySuccessMessage("Successfully Modify Password");
            }
        }else{
            return ServerResponse.createByErrorMessage("Token is wrong, please get a new Token for reset password");
        }
        return ServerResponse.createByErrorMessage("Modify password unsuccessfully");
    }

    public ServerResponse<String> resetPassword(String passwordOld, String passwordNew, User user){
        //prevent horizontal excessive, want to check the user's old password, must specify whether this user,
        // because we will query a count (1), if you do not specify id
        // So the result is true, count > 0
        int resultCount = userMapper.checkPassword(MD5Util.MD5EncodeUtf8(passwordOld), user.getId());
        if(resultCount == 0){
            return ServerResponse.createByErrorMessage("The old password is wrong");
        }
        user.setPassword(MD5Util.MD5EncodeUtf8(passwordNew));
        int updateCount = userMapper.updateByPrimaryKeySelective(user);
        if(updateCount > 0){
            return ServerResponse.createBySuccessMessage("Successfully update password");
        }
        return ServerResponse.createByErrorMessage("Update password unsuccessfully");
    }

    public ServerResponse<User> updateInformation(User user){
        //username can't be updated
        //also need to check email, check if the new email is exist, if both email are the same, it cannot be the current user
        int resultCount = userMapper.checkEmailByUserId(user.getEmail(), user.getId());
        if(resultCount > 0){
            return ServerResponse.createByErrorMessage("The email is already exist, please use a new email to try");
        }
        User updateUser = new User();
        updateUser.setId(user.getId());
        updateUser.setEmail(user.getEmail());
        updateUser.setPhone(user.getPhone());
        updateUser.setQuestion(user.getQuestion());
        updateUser.setAnswer(user.getAnswer());

        int updateCount = userMapper.updateByPrimaryKeySelective(updateUser);
        if(updateCount > 0){
            return ServerResponse.createBySuccess("Update personal information sucessfully", updateUser);
        }
        return ServerResponse.createByErrorMessage("Update personal information unsucessfully");
    }

    public ServerResponse<User> getInformation(Integer userId){
        User user = userMapper.selectByPrimaryKey(userId);
        if(user==null){
            return ServerResponse.createByErrorMessage("Can't find the user");
        }
        user.setPassword(StringUtils.EMPTY);
        return ServerResponse.createBySuccess(user);
    }
}

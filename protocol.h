#pragma once

#ifndef PROTOCOL_H
#define PROTOCOL_H

enum class clientQuery {
	Register,
	Login,
	Logout,
	Message,
	PrivateMessage,
	NameChange
};

enum class serverResponse {
	OK,
	Registered, 
	LoginOK,
	WrongPassword,
	UserNotFound,
	UsernameExists,
	Message
};

inline const char* toStr(serverResponse resp) {
	switch (resp) {
	case serverResponse::OK: return "OK";
	case serverResponse::Registered: return "Registration successful";
	case serverResponse::LoginOK: return "Login successful";
	case serverResponse::WrongPassword: return "Wrong password";
	case serverResponse::UserNotFound: return "User not found";
	case serverResponse::UsernameExists: return "Username exists";
	default: return "Unknown response";
	}
}

#endif // !PROTOCOL_H

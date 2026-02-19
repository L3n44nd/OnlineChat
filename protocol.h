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
	Successful,
	Registered, 
	LoginOK,
	WrongPassword,
	UserNotFound,
	UsernameExists,
	Message, 
	PrivateMessage
};

inline const char* toStr(serverResponse resp) {
	switch (resp) {
	case serverResponse::Successful: return "Имя изменено";
	case serverResponse::Registered: return "Регистрация успешна";
	case serverResponse::LoginOK: return "Вход выполнен";
	case serverResponse::WrongPassword: return "Неверный пароль";
	case serverResponse::UserNotFound: return "Пользователь не найден";
	case serverResponse::UsernameExists: return "Имя занято";
	default: return "Неизвестный код ответа";
	}
}

#endif // !PROTOCOL_H


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
	PrivateMessage, 
	NameTooLong
};

inline const char* toStr(serverResponse resp) {
	switch (resp) {
	case serverResponse::Successful: return "Имя изменено";
	case serverResponse::Registered: return "Регистрация успешна";
	case serverResponse::LoginOK: return "Вход выполнен";
	case serverResponse::WrongPassword: return "Неверный пароль";
	case serverResponse::UserNotFound: return "Пользователь не найден";
	case serverResponse::UsernameExists: return "Имя занято";
	case serverResponse::NameTooLong: return "Слишком длинное имя";
	default: return "Неизвестный код ответа";
	}
}

inline const char* toStrQ(clientQuery query) {
	switch (query)
	{
	case clientQuery::Register: return "Регистрация";
	case clientQuery::Login: return "Авторизация";
	case clientQuery::Logout: return "Выход";
	case clientQuery::Message: return "Сообщение";
	case clientQuery::PrivateMessage: return "Личное сообщение";
	case clientQuery::NameChange: return "Смена имени";
	default: return "Неизвестный код запроса";
	}
}
#endif // !PROTOCOL_H

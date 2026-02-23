#include "wServer.h"
#include <QCryptographicHash>

wServerClass::wServerClass(QWidget* parent)
    : QWidget(parent) {

        setupDB();
        setupServer();
        setupTimer();
        ui.setupUi(this);
    }

void wServerClass::setupDB() {
    chatDB = QSqlDatabase::addDatabase("QSQLITE");
    chatDB.setDatabaseName("chat.db");
    if (!chatDB.open()) {
        ui.oField->append("Не удалось открыть БД");
        return;
    }

    QSqlQuery query;
    query.exec(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE, "
        "password TEXT,"
        "salt TEXT)"
    );
 
    query.exec(
        "CREATE TABLE IF NOT EXISTS history ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "senderId INTEGER NOT NULL, "
        "senderName TEXT, "
        "recipientId INTEGER, "
        "timestamp INTEGER NOT NULL, "
        "message TEXT)"
    );
}

void wServerClass::setupServer() {    
    server.listen(QHostAddress::LocalHost, 1402);
    connect(&server, &QTcpServer::newConnection, this, &wServerClass::onNewConnection);
}

void wServerClass::setupTimer() {
    updateOnlineNum = new QTimer(this);
    updateOnlineNum->setInterval(5000);
    updateOnlineNum->start();

    connect(updateOnlineNum, &QTimer::timeout, this, [this]() {
        ui.onlineField->setText(QString::number(socketToId.size()));
        });
}

void wServerClass::onNewConnection() {
    QTcpSocket* newClient = server.nextPendingConnection();
    int descr = newClient->socketDescriptor();
    connect(newClient, &QTcpSocket::readyRead, this, [this, newClient]() {
        while (true) {
            if (waitingForSize) {
                if (newClient->bytesAvailable() < 4) return;
                QByteArray sizeBytes = newClient->read(4);
                sizeOfData = sizeBytes.toInt();
                waitingForSize = false;
            }
            else {
                if (newClient->bytesAvailable() < sizeOfData) return;
                QByteArray data = newClient->read(sizeOfData);
                processClientMsg(newClient, data);
                waitingForSize = true;
            }
        }
        });

    connect(newClient, &QTcpSocket::disconnected, this, [this, newClient, descr]() {
        if (socketToId.contains(newClient)) {
            int userId = socketToId[newClient];
            ui.oField->append(QString("Клиент #%1 отключился").arg(descr));
            idToName.remove(userId);
            idToSocket.remove(userId);
            socketToId.remove(newClient);
            sendOnlineList();
        }
        newClient->deleteLater();
        });
}

void wServerClass::processClientMsg(QTcpSocket* client, const QByteArray& utf8msg) {
    QString strmsg = QString::fromUtf8(utf8msg);
    int code = strmsg.section(' ', 0, 0).toInt(); 
    QString textMsg = strmsg.section(' ', 1);
    clientQuery command = static_cast<clientQuery>(code);

    if (command != clientQuery::Logout) qLogger(client, command);

    switch (command)
    {
    case clientQuery::Register:
        handleRegistration(client, textMsg);
        break;
    case clientQuery::Login:
        handleLogin(client, textMsg);
        break;
    case clientQuery::Logout:
        handleLogout(client, textMsg);
        break;
    case clientQuery::Message:
        handleChatMsg(client, textMsg);
        break;
    case clientQuery::PrivateMessage:
        handlePrivateMsg(client, textMsg);
        break;
    case clientQuery::NameChange:
        handleNameChange(client, textMsg);
        break;
    case clientQuery::GetHistory:
        sendHistory(client, textMsg);
        break;
    default:
        break;
    }
}

void wServerClass::handleRegistration(QTcpSocket* client, const QString& msg) {
    QStringList msgParts = msg.split(' '); 
    QString username = msgParts[0];
    QString password = msgParts[1];
    
    QSqlQuery checkQuery;
    checkQuery.prepare("SELECT COUNT(username) FROM users WHERE username = :name");
    checkQuery.bindValue(":name", username);
    checkQuery.exec();

    int userId;
    bool regSuccessful = false;

    if (checkQuery.next() && checkQuery.value(0).toInt() == 0) {
        QString salt = generateSalt();
        QString strToHash = password + salt;
        QByteArray bArrHashedStr = QCryptographicHash::hash(strToHash.toUtf8(), QCryptographicHash::Sha256);
        QString strHashed = bArrHashedStr.toHex();

        QSqlQuery regQuery;
        regQuery.prepare("INSERT INTO users (username, password, salt) VALUES (:name, :psw, :slt)");
        regQuery.bindValue(":name", username);
        regQuery.bindValue(":psw", strHashed);
        regQuery.bindValue(":slt", salt);
        regQuery.exec();

        userId = regQuery.lastInsertId().toInt();
        idToName[userId] = username;
        idToSocket[userId] = client;
        socketToId[client] = userId;
        regSuccessful = true;
    }

    if (regSuccessful) {
        QString formatedMsg = QString("%1 %2").arg(userId).arg(username);
        sendPacket(client, serverResponse::Registered, formatedMsg);
        sendOnlineList();
        rLogger(client, serverResponse::Registered);
    }
    else {
        sendPacket(client, serverResponse::UsernameExists); 
        rLogger(client, serverResponse::UsernameExists);
    }
}

void wServerClass::handleLogin(QTcpSocket* client, const QString& msg) {
    QStringList msgParts = msg.split(' ');
    QString username = msgParts[0];
    QString password = msgParts[1];

    int userId;
    bool loginSuccessful = false;
    QSqlQuery checkDataQuery;
    checkDataQuery.prepare("SELECT password, salt, id FROM users WHERE username = :name");
    checkDataQuery.bindValue(":name", username);
    checkDataQuery.exec();

    if (checkDataQuery.next()) {
        QString hashFromDB = checkDataQuery.value(0).toString();
        QString saltFromDB = checkDataQuery.value(1).toString();
        userId = checkDataQuery.value(2).toInt();
        QByteArray bArrHash = QCryptographicHash::hash((password + saltFromDB).toUtf8(), QCryptographicHash::Sha256);
        QString hashedStr = bArrHash.toHex();

        if (hashedStr == hashFromDB) {
            idToName[userId] = username;
            idToSocket[userId] = client;
            socketToId[client] = userId;
            loginSuccessful = true;
        }
    }
    else {
        sendPacket(client, serverResponse::UserNotFound);
        rLogger(client, serverResponse::UserNotFound);
        return;
    }

    QString formatedMsg;

    if (loginSuccessful) {
        formatedMsg = QString("%1 %2").arg(userId).arg(username);  
        sendPacket(client, serverResponse::LoginOK, formatedMsg);
        sendOnlineList();
        rLogger(client, serverResponse::LoginOK);
    }
    else {
        sendPacket(client, serverResponse::WrongPassword);
        rLogger(client, serverResponse::WrongPassword);
    }
}

void wServerClass::handleNameChange(QTcpSocket* client, QString msg) {
    int userId = socketToId[client];
    bool changeSuccessful = false;
    QString formatedMsg;
    QString newUsername = std::move(msg);

    if (newUsername.length() > 14) {
        sendPacket(client, serverResponse::NameTooLong);
        return;
    }

    QSqlQuery checkQuery;
    checkQuery.prepare("SELECT COUNT(username) FROM users WHERE username = :name");
    checkQuery.bindValue(":name", newUsername);
    checkQuery.exec();

    if (checkQuery.next() && checkQuery.value(0).toInt() == 0) {
        QSqlQuery updateQuery;
        updateQuery.prepare("UPDATE users SET username = :newName WHERE id = :id");
        updateQuery.bindValue(":newName", newUsername);
        updateQuery.bindValue(":id", userId);
        updateQuery.exec(); 

        idToName[userId] = newUsername;
        changeSuccessful = true;
    }

    if (changeSuccessful) {
        sendPacket(client, serverResponse::Successful, newUsername);
        sendOnlineList();
        rLogger(client, serverResponse::Successful);
    }
    else {
        sendPacket(client, serverResponse::UsernameExists);
        rLogger(client, serverResponse::UsernameExists);
    } 
}

void wServerClass::handleChatMsg(QTcpSocket* client, const QString& msg) {
    int senderId = socketToId[client];
    QString formatedMsg = QString("%1 %2").arg(idToName[senderId]).arg(msg);

    for (auto cl : socketToId.keys()) {
        if (cl != client) sendPacket(cl, serverResponse::Message, formatedMsg);
        rLogger(cl, serverResponse::Message);
    }
    saveToDB(senderId, idToName[senderId], 0, msg);
}

void wServerClass::handlePrivateMsg(QTcpSocket* client, const QString& msg) {
    int recipientId = msg.section(' ', 0, 0).toInt();

    if (!idToSocket.contains(recipientId)) {
        sendPacket(client, serverResponse::UserNotFound);
        rLogger(client, serverResponse::UserNotFound);
        return;
    }

    int senderId = socketToId[client];
    QString msgForUser = msg.section(' ', 1);
    QString formatedMsg = QString("%1 %2 %3").arg(senderId).arg(idToName[senderId]).arg(msgForUser);

    sendPacket(idToSocket[recipientId], serverResponse::PrivateMessage, formatedMsg);
    saveToDB(senderId, idToName[senderId], recipientId, msgForUser);
    rLogger(idToSocket[recipientId], serverResponse::PrivateMessage);
}

void wServerClass::handleLogout(QTcpSocket* client, const QString& msg) {
    client->disconnectFromHost();
}

void wServerClass::sendOnlineList() {
    QStringList list;
    for (const auto& userId : idToName.keys()) {
        list << QString("%1 %2").arg(userId).arg(idToName[userId]);
    }

    QString response = list.join('\n');

    for (QTcpSocket* client : socketToId.keys()) {
        sendPacket(client, serverResponse::UpdateOnline, response);
        rLogger(client, serverResponse::UpdateOnline);
    }
}

void wServerClass::sendPacket(QTcpSocket* client, const serverResponse response, const QString& data) {
    int respCode = static_cast<int>(response);
    QString formatedData = data.isEmpty() ? QString::number(respCode) : QString("%1 %2").arg(respCode).arg(data);
    QByteArray bArrData = formatedData.toUtf8();
    int dataSize = bArrData.size();
    QByteArray packet = QByteArray::number(dataSize).rightJustified(4, '0') + bArrData;
    client->write(packet);
}

void wServerClass::sendHistory(QTcpSocket* client, const QString& msg) {
    int otherId = msg.toInt();
    QSqlQuery query;
    if (otherId != 0){
        query.prepare(
            "SELECT senderId, senderName, message FROM history "
            "WHERE (senderId = :sender AND recipientId = :recipient) "
            "OR (senderId = :recipient AND recipientId = :sender) "
            "ORDER BY timestamp"
        );
        query.bindValue(":sender", socketToId[client]);
        query.bindValue(":recipient", otherId);
        query.exec();

    }
    else {
        query.exec(
            "SELECT senderId, senderName, message FROM history "
            "WHERE recipientId = 0 "
            "ORDER BY timestamp"
        );
    }

    QStringList list;
    QString senderId;
    QString senderName;
    QString message;
    while (query.next()) {
        senderId = query.value(0).toString();
        senderName = query.value(1).toString();
        message = query.value(2).toString();
        list << QString("%1 %2 %3").arg(senderId).arg(senderName).arg(message);
    }

    QString response = QString("%1 %2").arg(otherId).arg(list.join('\n'));
    sendPacket(client, serverResponse::SendHistory, response);
    rLogger(client, serverResponse::SendHistory);
}

void wServerClass::saveToDB(const int senderId, const QString& senderName, const int recipientId, const QString& msg) {
    qint64 currTime = QDateTime::currentSecsSinceEpoch();

    QSqlQuery query;
    query.prepare("INSERT INTO history (senderId, senderName, recipientId, timestamp, message) VALUES (:sId, :sName, :rId, :time, :msg)");
    query.bindValue(":sId", senderId);
    query.bindValue(":sName", senderName);
    query.bindValue(":rId", recipientId);
    query.bindValue(":time", currTime);
    query.bindValue(":msg", msg);
    query.exec();
}

QString wServerClass::generateSalt() {
    QByteArray salt(16, Qt::Uninitialized);
    QRandomGenerator::global()->generate(salt.begin(), salt.end());
    return salt.toHex();
}

void wServerClass::qLogger(QTcpSocket* client, clientQuery query){
    QString text = QString("<font color='#821d8a'>[from: #%1]: %2</font>").arg(client->socketDescriptor()).arg(toStrQ(query));
    ui.oField->append(text);
}

void wServerClass::rLogger(QTcpSocket* client, serverResponse response) {
    QString text = QString("<font color='#ffa000'>[to: #%1]: %2</font>").arg(client->socketDescriptor()).arg(toStr(response));
    ui.oField->append(text);
}

wServerClass::~wServerClass() {
    server.close();
    for (auto client : socketToId.keys()) {
        client->disconnect();
    }
    socketToId.clear();
    idToSocket.clear();
    idToName.clear();
}

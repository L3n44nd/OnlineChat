# OnlineChat
Многопользовательский онлайн-чат. C++17, Qt 6 (widgets, network, sql).

Серверная часть:
  - SQLite
  - безопасное хранение паролей
  - логирование действий пользователей
  - одновременная обработка подключений
  - отображение количества онлайн-пользователей
  - автоматическая очистка истории сообщений раз в день если количество в БД превышает порог
  - кастомный протокол

1. Асинхронный TCP-сервер
  ```cpp
  QTcpServer server;  // Слушает входящие подключения
  QHash<QTcpSocket*, int> socketToId; // сокет -> ID пользователя
  QHash<int, QTcpSocket*> idToSocket; // ID пользователя -> сокет
  QHash<int, QString> idToName; // ID пользователя -> имя
  ```

2. База данных SQLite
    - в таблице users хранятся данные пользхователей
    - в таблице history хранится архив сообщений
    - запросы к БД с защитой от SQL-инъекций (prepare)

3. Безопасность
    - при регистрации генерируется соль, добавляется к паролю пользователя, полученная строка хэшируется SHA-256:
  ```cpp
  QString wServerClass::generateSalt() {
      QByteArray salt(16, Qt::Uninitialized);
      QRandomGenerator::global()->generate(salt.begin(), salt.end());
      return salt.toHex();
  }
  ```
  ```cpp
  QString salt = generateSalt(); 
  QString strToHash = password + salt;
  QByteArray bArrHashedStr = QCryptographicHash::hash(strToHash.toUtf8(), QCryptographicHash::Sha256);
  ```
4. Протокол
    - пакет имеет формат `[4 байта - размер данных][данные - код ответа и информация]`
    - коды запросов (clientQuery) и коды ответов (serverResponse) содержатся в общем файле protocol.h

5. Обмен пакетами
    - формирование пакета:
  ```cpp
 void wServerClass::sendPacket(QTcpSocket* client, const serverResponse response, const QString& data) {
    int respCode = static_cast<int>(response);
    QString formatedData = data.isEmpty() ? QString::number(respCode) : QString("%1 %2").arg(respCode).arg(data);
    QByteArray bArrData = formatedData.toUtf8();
    int dataSize = bArrData.size();
    QByteArray packet = QByteArray::number(dataSize).rightJustified(4, '0') + bArrData;
    client->write(packet);
}
```
  - получение пакета от клиента: 
```cpp
      connect(newClient, &QTcpSocket::readyRead, this, [this, newClient]() {
        while (true) {
            if (waitingForSize) {
                if (newClient->bytesAvailable() < 4) return; // если не пришли первые 4 байта ждём дальше
                QByteArray sizeBytes = newClient->read(4); // когда пришли читаем размер 
                sizeOfData = sizeBytes.toInt();
                waitingForSize = false;
            }
            else {
                if (newClient->bytesAvailable() < sizeOfData) return; // ждём весь пакет
                QByteArray data = newClient->read(sizeOfData); // читаем
                processClientMsg(newClient, data); //передаём в метод для обработки
                waitingForSize = true; // ждём размер следующего пакета
            }
        }
        });
```
  - последующая обработка в switch с разбиением по типу запроса:
```cpp
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
    ...
```
  - история рассылается при авторизации и открытии вкладки личных сообщений (по запросу клиента)
  - список онлайна рассылается при входе и выходе
  

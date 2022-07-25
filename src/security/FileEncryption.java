package security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


public class FileEncryption {

    /**
     * Вектор инициализации. Этот ключ используется в качестве начального во время шифрования и должен иметь
     * размерность 16байт(16символов).
     * Сообщение зашифрованное с помощью этого ключа нельзя будет расшифровать с другим ключем.
     */
    private final static String IV_KEY = "\"b4*1'XR%p-<paF>";

    /**
     * Как будет выполнено преобразование:
     * <Engine or Algorithm>/<Block Cipher>/<Padding method>
     * Engine: Глобальное преобразование
     * Block cipher: Преобразование блоков
     * Padding method: Как поступить, если блок не заполнен
     */
    private final static String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    /**
     * Какой алгоритм будет использоваться
     */
    private final static String ALGORITHM = "AES";

    /**
     * Максимальная длина ключа/пароля
     */
    private final static int KEY_LENGTH = 16;

    /**
     * Расширение зашифрованного файла
     */
    private final static String FILE_EXTENSION = ".enc";

    /**
     * Длина буфера, используемая при шифровании/дешифровании
     */
    private final static int BUFFER_LENGTH = 16 * 1024;

    /**
     * Устанавливает программу в ENCRYPT_MODE
     */
    public final static byte ENCRYPT_MODE = 0;

    /**
     * Устанавливает программу в DECRYPT_MODE
     */
    public final static byte DECRYPT_MODE = 1;

    /**
     * Токен, используемый для заполнения пароля в случае, если он недостаточно длинный, так как пароль должен
     * быть ровно 16 байт (16 символов ASCII), не больше и не меньше. Если пароль, полученный на конструкторе
     * содержит этот токен, генерируется исключение
     */
    private static final char PASSWORD_TOKEN = ' ';

    /**
     * Размер файла в байтах
     */
    private long fileSize;

    /**
     * Счетчик, используемый для увеличения количества обработанных байтов, чтобы можно было
     * иметь средний процент процесса шифрования/дешифрования
     */
    private long counter;

    /**
     * Файл, в который будут внесены изменения
     */
    private File file;

    /**
     * Пароль который будет использован
     */
    private String password;

    /**
     * Преобразование мода для ENCRYPT_MODE и DECRYPT_MODE
     */
    private byte mode;

    /**
     * Текущее состояние преобразования. Весь статус успешного преобразования файла:
     * "Инициализация"
     * "Шифрование/дешифрование"
     * "Отменена"
     * "Успешно зашифровано/расшифровано"
     * "Неправильный пароль или ошибка файла"
     */
    private String status;

    /**
     * Отмена процесса шифрования
     */
    private boolean aborting;

    /**
     * Создает новый экземпляр файла для шифрования/дешифрования
     * это должно быть завершено вызовом start()
     * @param path     строка пути с абсолютным путем к файлу, который будет расшифрован/зашифрован
     * @param password пароль, используемый в качестве ключа шифрования /дешифрования
     * @param mode     режим шифрования/дешифрования
     * @throws FileEncryptionException вызов исключения при ошибке
     */
    public FileEncryption(String path, String password, byte mode) throws FileEncryptionException {
        if (password.contains(String.valueOf(PASSWORD_TOKEN)) || password.length() > KEY_LENGTH) {
            throw new FileEncryptionException("Invalid password");
        }
        this.password = password;
        this.file = new File(path);
        if (!file.exists()) {
            throw new FileEncryptionException("Inexistent file");
        }
        this.fileSize = file.length();
        this.counter = 0;
        if (mode < 0 || mode > 1) {
            throw new FileEncryptionException("Invalid mode");
        }
        this.mode = mode;
        this.aborting = false;
        this.status = "Initializing";
    }

    /**
     * Получает название файла назначения:
     * Шифрование файла test.txt
     * - Если файл test.txt.enc уже существует, система
     * - проверит, существует ли файл "(1) test.txt.enc", если он существует
     * - он проверит, существует ли "(2) test.txt.enc" и так далее, пока не достигнет
     * - имя файла, которое еще не существует
     * Расшифровка файла test.txt.enc
     * - Если файл test.txt уже существует, система
     * - проверит, существует ли файл "(1) test.txt ", если это так
     * - он проверит, существует ли файл "(2) x.txt " и так далее, пока не достигнет
     * - имя файла, которое еще не существует
     *
     * @param fileName оригинальное имя файла
     * @return
     */
    private File getDestinationFile(String fileName, byte mode) {
        File temp = new File(fileName);
        for (int i = 1; temp.exists(); i++) {
            fileName = mode == ENCRYPT_MODE ? createAlternativeFileNameToEncrypt(i) : createAlternativeFileNameToDecrypt(i);
            temp = new File(fileName);
        }
        return temp;
    }

    /**
     * Основной метод шифрования
     */
    private void encrypt() {
        this.status = "Encrypting";
        FileInputStream fis = null;
        FileOutputStream fos = null;
        CipherOutputStream cout = null;
        try {
            fis = new FileInputStream(file);
            String fileName = file.getAbsolutePath() + FILE_EXTENSION;
            file = getDestinationFile(fileName, mode);
            fos = new FileOutputStream(file);
            byte keyBytes[] = validatePassword().getBytes();
            SecretKeySpec key = new SecretKeySpec(keyBytes, ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV_KEY.getBytes()));
            cout = new CipherOutputStream(fos, cipher);
            byte[] buffer = new byte[BUFFER_LENGTH];
            int read;
            while (!aborting && ((read = fis.read(buffer)) != -1)) {
                cout.write(buffer, 0, read);
                counter += read;
            }
            cout.flush();
            status = aborting? "Canceled" : "Successfully encrypted";
        } catch (IOException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            aborting = true;
            status = e.getMessage();
        } finally {
            finish(cout, fos, fis);
        }
    }

    /**
     * Завершает процесс преобразования, закрывая все потоки и удаляя файл, если он был прерван
     * @param closeables закрывает потоки
     */
    private void finish(Closeable... closeables) {
        counter = fileSize;
        for (Closeable closeable : closeables) {
            try {
                closeable.close();
            } catch (Exception e) {
            }
        }
        if (aborting) file.delete();
    }

    /**
     * Отслеживает ход трансформации:
     * 1.0, если он завершен
     * 0.0, если он еще не начался
     * 0.5, если он находится в середине процесса
     *
     * @return ход преобразования
     */
    public double getProgress() {
        return 1.0 * counter / fileSize;
    }

    /**
     * Безопасно прерывает процесс преобразования
     */
    public void abort() {
        this.aborting = true;
    }

    /**
     * Возвращает абсолютный путь без расширения
     * Пример: example/file.txt > example/file
     * @return  абсолютный путь без расширения
     */
    private String getAbsolutePathWithoutExtension() {
        return file.getAbsolutePath().substring(0, file.getAbsolutePath().lastIndexOf('.'));
    }

    /**
     * Основной метод дешифрования
     */
    private void decrypt() {
        status = "Decrypting";
        FileInputStream fis = null;
        FileOutputStream fos = null;
        CipherInputStream cin = null;
        try {
            fis = new FileInputStream(file);
            String fileName = getAbsolutePathWithoutExtension();
            file = getDestinationFile(fileName, mode);
            fos = new FileOutputStream(file);
            byte keyPassword[] = validatePassword().getBytes();
            SecretKeySpec key = new SecretKeySpec(keyPassword, ALGORITHM);
            Cipher decrypt = Cipher.getInstance(TRANSFORMATION);
            decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV_KEY.getBytes()));
            cin = new CipherInputStream(fis, decrypt);
            byte[] buffer = new byte[BUFFER_LENGTH];
            int read;
            while (!aborting && ((read = cin.read(buffer)) > 0)) {
                fos.write(buffer, 0, read);
                counter += read;
            }
            fos.flush();
            status = aborting? "Canceled" : "Successfully decrypted";
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IOException | InvalidAlgorithmParameterException e) {
            aborting = true;
            status = "Wrong password or broken file";
        } finally {
            finish(fos, cin, fis);
        }
    }

    /**
     * Добавляет PASSWORD_TOKEN для заполнения заданного пароля так как
     * пароль должен быть ровно 16 байт (16 символов).
     * Пример: "test" переходит в "test", предполагая, что PASSWORD_TOKEN
     * значение равно ' ' (пробел).
     * Этот метод на самом деле безопасен, так как в конструкторе генерируется исключение, если
     * данный пароль содержит PASSWORD_TOKEN.
     * @return обновленный пароль
     */
    private String validatePassword() {
        StringBuilder temp = new StringBuilder(password);
        while (temp.length() < KEY_LENGTH) {
            temp.insert(0, PASSWORD_TOKEN);
        }
        return temp.toString();
    }

    private String createAlternativeFileNameToEncrypt(int i) {
        StringBuilder sb = new StringBuilder();
        if (file.getParent() != null) {
            sb.append(file.getParent()).append(File.separator);
        }
        // Добавляет "(i) " в начале, а также в расширении
        sb.append("(").append(i).append(") ").append(file.getName()).append(FILE_EXTENSION);
        return sb.toString();
    }

    private String createAlternativeFileNameToDecrypt(int i) {
        StringBuilder sb = new StringBuilder();
        if (file.getParent() != null) {
            sb.append(file.getParent()).append(File.separator);
        }
        // Добавляет "(i) " в начале, а также удаляет расширение
        sb.append("(").append(i).append(") ").append(file.getName().substring(0, file.getName().lastIndexOf(FILE_EXTENSION)));
        return sb.toString();
    }

    /**
     * Получение статуса
     * @return статус
     */
    public String getStatus() {
        return status;
    }

    /**
     * Старт
     */
    public void start() {
        if (mode == ENCRYPT_MODE) {
            encrypt();
        } else if (mode == DECRYPT_MODE) {
            decrypt();
        }
    }
}

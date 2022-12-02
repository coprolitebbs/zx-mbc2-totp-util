# zx-mbc2-totp-util
Realise utility to generate SHA1 TOTP 

Утилита генерации TOTP-токена на базе алгоритма SHA1 для компьютера Z80-MBC2

Еще недоделано.

Предполагается компилирование и использование в среде CPM 3.0

Сборка
* Сборку для тестирования можно провести посредством gcc. Для этого используйте команду
  > # gcc -Wall ./ttp.c -o ./ttp
* Сборку можно произвести с помощью компилятора Hi-Tech C для систем на базе процессора Z80. 
    Для этого нужно:
    1. Скачать и установить ZXCC (стандартными средствами ./configure / make / make install),
    2, Клонировать из репозитория компилятор Hi-Tech C:
	> # https://github.com/agn453/HI-TECH-Z80-C.git
    3. Перейти в директорию HI-TECH-Z80-C/dist и выполнить команду преобразования всех имен файлов внутри в нижний регистр, иначе zxcc просто ничего не увидит
	> # rename -f 'y/A-Z/a-z/' *
    4. Скопировать в эту же директорию файлы проекта ttp.c и ttp.h
    5. Скомпилировать проект из текущей директории командой 
	> # zxc ttp.c

* Запуск можно произвести эмулятором zxcc из директории, где собирался проект (HI-TECH-Z80-C/dist), для этого используйте команду 
    # zxcc ttp -[кодированный ключ base32]
Например, есть кодированный ключ "VKVKVKVK", (его можно получить любым способомБ напримерБ онлайн-конвертером из 16ричной строки в base32),
тогда команда будет выглядеть как 
    # zxcc ttp -VKVKVKVK
* Запуск скомпилированной gcc версии будет выглядеть как 
    #./ttp VKVKVKVK


Ссылки:
* https://github.com/lucadentella/TOTP-Arduino
* https://gist.github.com/syzdek/eba233ca33e1b5a45a99

Мануал по Hi-Tech C
* https://github.com/serge-404/HI-TECH-C-V3.09/blob/master/Z80DOC.TXT

Ссылка на Hi-Tech C используемый для компиляции проекта под CP-M
* https://github.com/agn453/HI-TECH-Z80-C

Онлайн-генератор TOTP для сравнения генерации
* https://totp.danhersam.com/

Эмулятор среды CP-M в Linux для запуска компилятора Hi-Tech C и тестирования проекта
* https://github.com/agn453/ZXCC



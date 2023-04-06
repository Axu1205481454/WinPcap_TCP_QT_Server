/********************************************************************************
** Form generated from reading UI file 'qt_winpcap_server.ui'
**
** Created by: Qt User Interface Compiler version 5.12.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_QT_WINPCAP_SERVER_H
#define UI_QT_WINPCAP_SERVER_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_QT_WinPcap_ServerClass
{
public:

    void setupUi(QWidget *QT_WinPcap_ServerClass)
    {
        if (QT_WinPcap_ServerClass->objectName().isEmpty())
            QT_WinPcap_ServerClass->setObjectName(QString::fromUtf8("QT_WinPcap_ServerClass"));
        QT_WinPcap_ServerClass->resize(600, 400);

        retranslateUi(QT_WinPcap_ServerClass);

        QMetaObject::connectSlotsByName(QT_WinPcap_ServerClass);
    } // setupUi

    void retranslateUi(QWidget *QT_WinPcap_ServerClass)
    {
        QT_WinPcap_ServerClass->setWindowTitle(QApplication::translate("QT_WinPcap_ServerClass", "QT_WinPcap_Server", nullptr));
    } // retranslateUi

};

namespace Ui {
    class QT_WinPcap_ServerClass: public Ui_QT_WinPcap_ServerClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_QT_WINPCAP_SERVER_H

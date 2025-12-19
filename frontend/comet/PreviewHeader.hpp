#pragma once

#include <QWidget>
#include <QHBoxLayout>

class PreviewHeader : public QWidget
{
    Q_OBJECT
    
public:
    PreviewHeader(QWidget *parent = nullptr);
    ~PreviewHeader();

private:
    void initUI();

private:
    QHBoxLayout *m_layout;
};
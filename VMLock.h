#pragma once

#include <QtWidgets/QMainWindow>
#include <QDragEnterEvent>
#include <QMimeData>
#include "ui_VMLock.h"
#include "PortableExecutable.h"

class VMLock : public QMainWindow
{
  Q_OBJECT

public:
  VMLock(QWidget *parent = Q_NULLPTR);

private slots:
  void OnBuildClicked();

private:
  void ProcessFile(std::string path);
  void dragEnterEvent(QDragEnterEvent* e);
  void dropEvent(QDropEvent* e);

  Ui::VMLockClass ui;
  PortableExecutable* PE;
};

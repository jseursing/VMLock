#include "VMLock.h"
#include "VMUtils.h"
#include <QMessageBox>
#include <QTreeWidget>
#include <vector>

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  Constructor
// 
/////////////////////////////////////////////////////////////////////////////////////////
VMLock::VMLock(QWidget *parent) : 
  QMainWindow(parent),
  PE(0)
{
  // Initialize UI
  ui.setupUi(this);
  setAcceptDrops(true);

  // Retrieve and populate UID information
  VMUtils::GenerateUniqueIdentifier();
  ui.UIDEdit->setText(VMUtils::UidString().c_str());
  ui.RUIDEdit->setText(VMUtils::FileSysString().c_str());

  // Connect components to signals
  connect(ui.BuildButton, &QPushButton::clicked, this, &VMLock::OnBuildClicked);
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  OnBuildClicked
// 
/////////////////////////////////////////////////////////////////////////////////////////
void VMLock::OnBuildClicked()
{
  if (0 != PE)
  {
    // Retrieve function count
    QStringList strAddresses = ui.FunctionsEdit->toPlainText().split("\n");

    // Create the new section
    PE->InitializeNewSection(ui.SectionEdit->text().toStdString().c_str());

    // Retrieve local data
    unsigned int uid = strtoul(ui.UIDEdit->text().toStdString().c_str(), 0, 16);

    unsigned char ruid[FILE_SYS_LEN] = { 0 };
    for (unsigned int i = 0; i < ui.RUIDEdit->text().length(); i += 2)
    {
      std::string ch = ui.RUIDEdit->text().toStdString().substr(i, 2);
      ruid[i / 2] = strtoul(ch.c_str(), 0, 16);
    }

    // Before virtualizing anything, we need to set the uid information
    VMUtils::SetUniqueIdentifier(uid, ruid);

    // Virtualize all listed functions
    std::vector<unsigned int> offsets(strAddresses.size(), 0);
    std::vector<unsigned int> lengths(offsets.size(), 0);

    // Base address should be the pointer to the file buffer.
    unsigned int deleteCount = 0;
    unsigned int bufAddress = reinterpret_cast<unsigned int>(PE->GetBaseAddress());
    for (unsigned int i = 0; i < strAddresses.size(); ++i)
    {
      if (0 == strAddresses[i].length())
      {
        continue;
      }

      offsets[i] = strtoul(strAddresses[i].toStdString().c_str(), 0, 16);
      lengths[i] = VMUtils::VirtualizeFunction
                   (reinterpret_cast<void*>(bufAddress + offsets[i]));

      // Destroy the export entry
      unsigned int offset = reinterpret_cast<unsigned int>
                            (VMUtils::GetRVAFuncOffset(offsets[i]));
      
      if (true == PE->DestroyExportFunction(offset, deleteCount))
      {
        ++deleteCount;
      }
    }

    // Build a buffer containing our uid information and function data.
    std::vector<unsigned char> buffer;
    VMUtils::BuildVMBuffer(uid, ruid, offsets, lengths, buffer);

    // Write buffer data to file.
    PE->InsertIntoNewSection(buffer.data(), buffer.size(), 0);

    // Encrypt the new section
    VMUtils::XORvSection(PE->PtrToLastSectionBuf(0), buffer.size());

    // Finalize section and close file.
    PE->FinalizeNewSection(buffer.size());

    QMessageBox::information(this, "VMLock", "Done");
    delete PE;
    PE = 0;
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  ProcessFile
// 
/////////////////////////////////////////////////////////////////////////////////////////
void VMLock::ProcessFile(std::string path)
{
  if (0 != PE)
  {
    // Release data
    delete PE;
    PE = 0;
  }

  // Backup the file
  std::string packedFile = path.substr(0, path.length() - 4); // Remove ".exe"
  packedFile += "-VP.exe";

  PortableExecutable::BackupFile(path, packedFile);

  // Open file
  PE = new PortableExecutable();
  if (false == PE->Attach(packedFile.c_str(), 1024))
  {
    QMessageBox::warning(this, "Error", "Failed loading file");
    return;
  }

  // Clear tree
  ui.PETree->clear();

  // Retrieve PE file information and populate components
  QTreeWidgetItem* item = new QTreeWidgetItem();
  QTreeWidgetItem* subItem = 0;

  // NT Headers
  item->setText(0, "NT Headers");
  ui.PETree->addTopLevelItem(item);
  subItem = new QTreeWidgetItem(item);
  subItem->setText(0, "Image Base: " +
    QString::number(PE->NtHeaders->OptionalHeader.ImageBase, 16));
  subItem = new QTreeWidgetItem(item);
  subItem->setText(0, "Image Size: " +
    QString::number(PE->NtHeaders->OptionalHeader.SizeOfImage, 16));
  subItem = new QTreeWidgetItem(item);
  subItem->setText(0, "Entry Point: " +
    QString::number(PE->NtHeaders->OptionalHeader.AddressOfEntryPoint, 16));
  subItem = new QTreeWidgetItem(item);
  subItem->setText(0, "Number Of Sections: " +
    QString::number(PE->NtHeaders->FileHeader.NumberOfSections, 16));

  // Individual Section Headers
  IMAGE_SECTION_HEADER* section = PE->FirstSectionHeader;
  for (unsigned int i = 0; i < PE->NtHeaders->FileHeader.NumberOfSections; ++i)
  {
    if (0 != section)
    {
      std::string sectionName(8, 0);
      memcpy(&sectionName[0], section->Name, sectionName.size());

      item = new QTreeWidgetItem();
      item->setText(0, sectionName.c_str());
      ui.PETree->addTopLevelItem(item);
      subItem = new QTreeWidgetItem(item);
      subItem->setText(0, "Pointer to Raw Data: " +
        QString::number(section->PointerToRawData, 16));
      subItem = new QTreeWidgetItem(item);
      subItem->setText(0, "Size of Raw Data: " +
        QString::number(section->SizeOfRawData, 16));
      subItem = new QTreeWidgetItem(item);
      subItem->setText(0, "Virtual Address: " +
        QString::number(section->VirtualAddress, 16));
    }

    ++section;
  }

  // Exports - I fucken hate pointers...
  item = new QTreeWidgetItem();
  item->setText(0, "Export Address Table");
  ui.PETree->addTopLevelItem(item);

  for (unsigned int i = 0; i < PE->ExportDirectory->NumberOfFunctions; ++i)
  {
    unsigned int addressOfNames = PE->ExportDirectory->AddressOfNames;
    PE->SetExportRVA(addressOfNames);

    unsigned int funcNameAddress = reinterpret_cast<unsigned int*>
      (reinterpret_cast<char*>(PE->GetBaseAddress()) + addressOfNames)[i];
    PE->SetExportRVA(funcNameAddress);

    unsigned int addressOfOrdinals = PE->ExportDirectory->AddressOfNameOrdinals;
    PE->SetExportRVA(addressOfOrdinals);

    unsigned int addressOfFunctions = PE->ExportDirectory->AddressOfFunctions;
    PE->SetExportRVA(addressOfFunctions);

    char* functionName = reinterpret_cast<char*>
      (reinterpret_cast<char*>(PE->GetBaseAddress()) + funcNameAddress);
    unsigned short functionOrd = reinterpret_cast<unsigned short*>
      (reinterpret_cast<char*>(PE->GetBaseAddress()) + addressOfOrdinals)[i];
    unsigned int functionAddr = reinterpret_cast<unsigned int*>
      (reinterpret_cast<char*>(PE->GetBaseAddress()) + addressOfFunctions)[i];
    unsigned int funcOffset = reinterpret_cast<unsigned int>
      (VMUtils::GetFuncOffsetRVA(functionAddr));

    subItem = new QTreeWidgetItem(item);
    subItem->setText(0, functionName);
    subItem = new QTreeWidgetItem(subItem);
    subItem->setText(0, QString::number(funcOffset, 16));
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  dragEnterEvent
// 
/////////////////////////////////////////////////////////////////////////////////////////
void VMLock::dragEnterEvent(QDragEnterEvent* e)
{
  if (true == e->mimeData()->hasUrls())
  {
    e->acceptProposedAction();
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  dropEvent
// 
/////////////////////////////////////////////////////////////////////////////////////////
void VMLock::dropEvent(QDropEvent* e)
{
  for (const QUrl& url : e->mimeData()->urls())
  {
    QString filePath = url.toLocalFile();
    ProcessFile(filePath.toStdString());
    break;
  }
}
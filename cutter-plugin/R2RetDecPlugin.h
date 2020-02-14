/**
 * @file cutter-plugin/R2RetDecPlugin.h
 * @brief Cutter plugin definition. Registers RetDec decompiler.
 *
 * This file is based on cutter_plugin/R2GhidraPlugin.h
 * in projcet https://github.com/radareorg/r2ghidra-dec.
 */

#ifndef RETDEC_R2PLUGIN_R2RETDECPLUGIN_H
#define RETDEC_R2PLUGIN_R2RETDECPLUGIN_H

#include <QObject>
#include <QtPlugin>
#include <plugins/CutterPlugin.h>

class R2RetDecPlugin : public QObject, CutterPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.radare.cutter.plugins.r2retdec")
    Q_INTERFACES(CutterPlugin)

public:
    void setupPlugin() override;
    void setupInterface(MainWindow *main) override;
    void registerDecompilers() override;

    QString getName() const          { return "RetDec Decompiler (retdec-r2plugin)"; }
    QString getAuthor() const        { return "Avast"; }
    QString getDescription() const   { return "RetDec plugin for Cutter"; }
    QString getVersion() const       { return "0.1.1"; }
};


#endif // RETDEC_R2PLUGIN_R2RETDECPLUGIN_H

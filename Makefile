THEOS ?= $(HOME)/theos
ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless
PACKAGE_VERSION = 1.41.0

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = AppleSigner
AppleSigner_FILES = SigningPlanExporter.m DEREntitlementsDecoder.m EntitlementsProfileComparator.m EntitlementsAudit.m main.m AppDelegate.m ViewController.m ProfileInspector.m IPAInspector.m IPAExtractor.m SignatureAudit.m SigningPreparation.m MachOSignatureInspector.m CodeDirectoryBuilder.m SuperBlobBuilder.m MachOSignatureStager.m SigningIdentityVerifier.m CMSPreflight.m CMSDetachedBuilder.m CMSDetachedVerifier.m
AppleSigner_FRAMEWORKS = UIKit UniformTypeIdentifiers Security
AppleSigner_LIBRARIES = z
AppleSigner_CFLAGS = -fobjc-arc -Wno-error=nullability-completeness
AppleSigner_INSTALL_PATH = /Applications

include $(THEOS_MAKE_PATH)/application.mk

after-install::
	install.exec "uicache -p /Applications/AppleSigner.app || true"

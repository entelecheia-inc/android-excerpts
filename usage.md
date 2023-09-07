Output of 

```
git grep cryptoManager > ../android-excerpts/usage.txt
```

is,

```
app/src/main/java/android/app/sendnoteapp/service/MyFirebaseMessagingService.kt:        val cryptoManager = CryptographicManager()
app/src/main/java/android/app/sendnoteapp/service/MyFirebaseMessagingService.kt:            cryptoManager.decryptString(it.baseContext ?: "", cryptoManager.RetrieveKey())
app/src/main/java/android/app/sendnoteapp/service/MyFirebaseMessagingService.kt:        var noteStr = cryptoManager.decryptString(it.note ?: "", cryptoManager.RetrieveKey())
app/src/main/java/android/app/sendnoteapp/service/MyFirebaseMessagingService.kt:        val cryptoManager = CryptographicManager()
app/src/main/java/android/app/sendnoteapp/service/MyFirebaseMessagingService.kt:            cryptoManager.decryptString(it.baseContext ?: "", cryptoManager.RetrieveKey())
app/src/main/java/android/app/sendnoteapp/ui/createnote/ComposeNoteViewModel.kt:        cryptoManager: CryptographicManager,
app/src/main/java/android/app/sendnoteapp/ui/createnote/ComposeNoteViewModel.kt:            cryptoManager.encryptedString(pin, cryptoManager.RetrieveKey()),
app/src/main/java/android/app/sendnoteapp/ui/createnote/ComposeNoteViewModel.kt:            cryptoManager.encryptedString(noteStr, cryptoManager.RetrieveKey()),
app/src/main/java/android/app/sendnoteapp/ui/createnote/ComposeNoteViewModel.kt:            baseContext = cryptoManager.encryptedString(baseContext, cryptoManager.RetrieveKey()),
app/src/main/java/android/app/sendnoteapp/ui/createnote/CreateNoteDetailsFragment.kt:            val cryptoManager = CryptographicManager()
app/src/main/java/android/app/sendnoteapp/ui/createnote/CreateNoteDetailsFragment.kt:                cryptoManager.decryptString(it.pin ?: "", cryptoManager.RetrieveKey())
app/src/main/java/android/app/sendnoteapp/ui/createnote/CreateNoteFragment.kt:                    val cryptoManager = CryptographicManager()
app/src/main/java/android/app/sendnoteapp/ui/createnote/CreateNoteFragment.kt:                        it, encryptString, cryptoManager, requireActivity(), noteType
app/src/main/java/android/app/sendnoteapp/ui/detail_screen/ViewNoteFragment.kt:        val cryptoManager = CryptographicManager()
app/src/main/java/android/app/sendnoteapp/ui/detail_screen/ViewNoteFragment.kt:        return@withContext cryptoManager.decryptString(
app/src/main/java/android/app/sendnoteapp/ui/detail_screen/ViewNoteFragment.kt:            CommonMethod.requestNote?.note ?: "", cryptoManager.RetrieveKey()
```

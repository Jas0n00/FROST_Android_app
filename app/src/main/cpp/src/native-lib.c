#include <jni.h>
#include <stdio.h>
#include <stdlib.h>

extern void execute_signing(int threshold, int participants, const char* message, int* indices);

// JNI function to call from Java
JNIEXPORT void JNICALL Java_cz_but_frost_MainActivity_executeSigning(JNIEnv *env, jobject obj, jint threshold, jint participants, jstring message, jintArray indices) {
    // Convert jstring to C string
    const char *nativeMessage = (*env)->GetStringUTFChars(env, message, 0);

    // Get the indices array
    jint *nativeIndices = (*env)->GetIntArrayElements(env, indices, 0);

    // Call the execute_signing function from C code
    execute_signing(threshold, participants, nativeMessage, nativeIndices);

    // Release resources
    (*env)->ReleaseStringUTFChars(env, message, nativeMessage);
    (*env)->ReleaseIntArrayElements(env, indices, nativeIndices, 0);
}

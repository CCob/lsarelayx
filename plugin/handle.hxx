#ifndef HANDLE_HXX
#define HANDLE_HXX

#include <windows.h>
#include <memory>

template <typename D, D fn>
using deleter_from_fn = std::integral_constant<D, fn>;

template <typename T, typename D, D fn>
using my_unique_ptr = std::unique_ptr<T, deleter_from_fn<D, fn>>;

struct HandleDeleter{
    typedef HANDLE pointer;
    void operator()(HANDLE h){
        if(h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }
};

typedef std::unique_ptr<HANDLE, HandleDeleter> win32_handle;


template <typename D, D fn>
using deleter_from_fn = std::integral_constant<D, fn>;

template <typename T, typename D, D fn>
using my_unique_ptr = std::unique_ptr<T, deleter_from_fn<D, fn>>;

template <class T>
struct LocalFreeDeleter{
    void operator()(T* type){
        if(type != nullptr)
            LocalFree(type);
    }
};

typedef std::unique_ptr<SID, LocalFreeDeleter<SID>> win32_psid;
typedef std::unique_ptr<TOKEN_GROUPS> win32_tokengroups;

#endif // HANDLE_HXX

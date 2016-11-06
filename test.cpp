#include <iostream>
using namespace std;


int main()
{
    
    int e = 65537;
    long long phi =536945816999843550;
    int d = 3;
    while (d<phi)
    {
        if ((d*e)%phi == 1)
        {
            break;
        }
        d = d+1;
    }
    cout<<d<endl;

    return 0;
}

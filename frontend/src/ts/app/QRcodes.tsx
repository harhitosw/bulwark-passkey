import React from "react";
import QRCode from 'react-qr-code'
import { base64ToBytes, bytesToBase64, setImmediate } from "../core/util";
import { Identity } from "../../proto/data";
import { callRPC } from "../core/rpc";
interface QRCodeSate{
  identities : Identity[]
  isLoading: boolean
}
function parseData(id : Identity[]) : string{
 
    const Id = id[0].id
    if(Id!==undefined){
      return Buffer.from(Id).toString('base64')
    } 
    throw new Error("some Error Occurred");
    
  
}
export async function getIdentities(): Promise<Identity[]> {
  const protosRaw = (await callRPC("getIdentities")) as string[];
  const identities = [];
  for (const protoRaw of protosRaw) {
      const protoBytes = base64ToBytes(protoRaw); // Wails events converts bytes to base64
      const id = Identity.fromBinary(protoBytes, {
          readUnknownField: "throw",
      });
      identities.push(id);
  }
  return identities;
}
export class QRcode extends React.Component<{},QRCodeSate>{

  constructor(props :{}){
    super(props);
    this.state = {
      identities : [],
      isLoading : true,
    };
  }
   async componentDidMount(){
      const fetchedIdentities = await getIdentities();
      this.setState({identities : fetchedIdentities,isLoading:false});
  }
  render(){
    if(this.state.isLoading){
      return <div>Loading.....</div>
    } 
       const ID = this.state.identities[1].id ?bytesToBase64(this.state.identities[1].id) : "";
       const publicKey = this.state.identities[1].publicKey? bytesToBase64(this.state.identities[1].publicKey) : "";
       const privateKey= this.state.identities[1].privateKey? bytesToBase64(this.state.identities[1].privateKey) : "";
       
       const finalString = ID +" "+ publicKey+" "+privateKey;


    const qrCode = (
      <QRCode 
        id="qrcodeid"
        size={200} 
        value={finalString}
        bgColor="white"
        fgColor="black"
        level="H"  
        />
    );
    return (
      <div className="qr-codes"
      style={{
        display : 'flex',
        alignItems:'center',
        justifyContent :'center',
        verticalAlign : 'center'
     }}
      >
     <div 
     className="qr_container">{qrCode}
     </div>
  
    </div>
    );
   }
}